/*
 * false_sharing_benchmark.c
 *
 * Runs all five false sharing scenarios sequentially.
 * Designed as ground truth validation for a PIN-based false sharing detector.
 *
 * Scenarios:
 *   0 - FALSE SHARING:         threads write adjacent fields on the same cache line
 *   1 - NO FALSE SHARING:      threads write fields on separate cache lines (padded)
 *   2 - PRODUCER/CONSUMER:     head/tail of a queue on same cache line
 *   3 - TRUE SHARING:          threads write the exact same variable (data race,
 *                               NOT false sharing — detector must distinguish this)
 *   4 - NO SHARING:            each thread has its own cache-line-aligned buffer
 *
 * Compile:
 *   gcc -O0 -g -pthread -o false_sharing_benchmark false_sharing_benchmark.c
 *
 * Run:
 *   ./false_sharing_benchmark [threads] [iterations]
 *
 * Run under PIN:
 *   pin -t your_tool.so -- ./false_sharing_benchmark [threads] [iterations]
 */

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* =========================================================================
 * Constants
 * ========================================================================= */

#define CACHE_LINE_SIZE    64
#define MAX_THREADS        8
#define DEFAULT_THREADS    4
#define DEFAULT_ITERATIONS 10000000
#define NUM_SCENARIOS      5


/* =========================================================================
 * Shared data structures
 * ========================================================================= */

/* Scenario 0: all four counters on one cache line */
struct FalseSharingCounters {
    uint64_t c0;
    uint64_t c1;
    uint64_t c2;
    uint64_t c3;
};
struct FalseSharingCounters fs_counters;

/* Scenario 1: each counter padded to its own cache line */
struct PaddedCounter {
    uint64_t value;
    char     pad[CACHE_LINE_SIZE - sizeof(uint64_t)];
};
struct PaddedCounter padded_counters[MAX_THREADS]
    __attribute__((aligned(CACHE_LINE_SIZE)));

/* Scenario 2: producer/consumer queue with head and tail on same cache line */
struct SharedQueue {
    uint64_t head;
    uint64_t tail;
};
struct SharedQueue queue;

/* Scenario 3: true sharing — all threads write the same variable */
uint64_t true_shared_counter = 0;

/* Scenario 4: each thread has its own cache-line-aligned slot */
typedef struct {
    uint64_t value;
    char     pad[CACHE_LINE_SIZE - sizeof(uint64_t)];
} CacheLineSlot;
CacheLineSlot no_share_buffers[MAX_THREADS]
    __attribute__((aligned(CACHE_LINE_SIZE)));


/* =========================================================================
 * Thread argument structure
 * ========================================================================= */
typedef struct {
    int      thread_id;
    int      scenario;
    uint64_t iterations;
} ThreadArgs;


/* =========================================================================
 * Worker thread
 * ========================================================================= */
void* worker(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;
    uint64_t i;

    switch (args->scenario) {
        case 0:
            for (i = 0; i < args->iterations; i++) {
                switch (args->thread_id) {
                    case 0: fs_counters.c0++; break;
                    case 1: fs_counters.c1++; break;
                    case 2: fs_counters.c2++; break;
                    default: fs_counters.c3++; break;
                }
            }
            break;

        case 1:
            for (i = 0; i < args->iterations; i++) {
                padded_counters[args->thread_id].value++;
            }
            break;

        case 2:
            for (i = 0; i < args->iterations; i++) {
                if (args->thread_id == 0)
                    queue.head++;
                else
                    queue.tail++;
            }
            break;

        case 3:
            for (i = 0; i < args->iterations; i++) {
                true_shared_counter++;
            }
            break;

        case 4:
            for (i = 0; i < args->iterations; i++) {
                no_share_buffers[args->thread_id].value++;
            }
            break;
    }

    return NULL;
}


/* =========================================================================
 * Timing
 * ========================================================================= */
static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}


/* =========================================================================
 * Run a single scenario
 * ========================================================================= */
static void run_scenario(int scenario, int nthreads, uint64_t iterations) {
    const char* names[] = {
        "false sharing",
        "no false sharing (padded)",
        "producer/consumer false sharing",
        "true sharing (data race)",
        "no sharing"
    };

    /* Reset all shared state before each scenario */
    memset(&fs_counters,        0, sizeof(fs_counters));
    memset(padded_counters,     0, sizeof(padded_counters));
    memset(&queue,              0, sizeof(queue));
    true_shared_counter = 0;
    memset(no_share_buffers,    0, sizeof(no_share_buffers));

    printf("=== Scenario %d: %s ===\n", scenario, names[scenario]);

    pthread_t  threads[MAX_THREADS];
    ThreadArgs args[MAX_THREADS];

    double t_start = now_seconds();

    for (int i = 0; i < nthreads; i++) {
        args[i].thread_id  = i;
        args[i].scenario   = scenario;
        args[i].iterations = iterations;
        int rc = pthread_create(&threads[i], NULL, worker, &args[i]);
        if (rc != 0) {
            fprintf(stderr, "Failed to create thread %d: error %d\n", i, rc);
            exit(1);
        }
    }

    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    double elapsed = now_seconds() - t_start;

    printf("Elapsed: %.3f s | Writes/sec: %.0f million\n",
           elapsed,
           (double)(iterations * (uint64_t)nthreads) / elapsed / 1e6);

    printf("\n");
}


/* =========================================================================
 * Memory layout diagnostic
 * ========================================================================= */
static void print_memory_layout(void) {
    printf("=== Memory layout ===\n");
    printf("Scenario 0 — fs_counters: c0=%p c1=%p c2=%p c3=%p (all cache line %p)\n",
           (void*)&fs_counters.c0, (void*)&fs_counters.c1,
           (void*)&fs_counters.c2, (void*)&fs_counters.c3,
           (void*)((uintptr_t)&fs_counters.c0 & ~(uintptr_t)(CACHE_LINE_SIZE-1)));
    printf("Scenario 1 — padded_counters[0..3] on separate cache lines\n");
    printf("Scenario 2 — queue.head=%p queue.tail=%p (cache line %p)\n",
           (void*)&queue.head, (void*)&queue.tail,
           (void*)((uintptr_t)&queue.head & ~(uintptr_t)(CACHE_LINE_SIZE-1)));
    printf("Scenario 3 — true_shared_counter=%p\n", (void*)&true_shared_counter);
    printf("Scenario 4 — no_share_buffers[0..3] on separate cache lines\n");
    printf("\n");
}


/* =========================================================================
 * Main
 * ========================================================================= */
int main(int argc, char* argv[]) {
    int      nthreads   = (argc > 1) ? atoi(argv[1]) : DEFAULT_THREADS;
    uint64_t iterations = DEFAULT_ITERATIONS;

    if (nthreads < 1 || nthreads > MAX_THREADS) {
        fprintf(stderr, "Thread count must be between 1 and %d\n", MAX_THREADS);
        return 1;
    }

    printf("Threads: %d  |  Iterations per thread: %llu\n\n",
           nthreads, (unsigned long long)iterations);

    print_memory_layout();

    for (int s = 0; s < NUM_SCENARIOS; s++)
        run_scenario(s, nthreads, iterations);

    return 0;
}