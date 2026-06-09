/*
 * false_sharing_benchmark.c
 *
 * Five ground-truth scenarios for the PIN cache-sharing detector.
 *
 * All mutable scenario data lives in BSS (zero-init at load time, no runtime
 * write from the main thread).  read_slot is const/rodata — never written at
 * runtime.  This ensures the only writes PIN records are from worker threads,
 * keeping exclusive-writer detection clean.
 *
 *   0 - TRUE SHARING:      all threads write the exact same variable
 *   1 - FALSE SHARING:     threads write exclusive fields on the same cache line
 *   2 - PRODUCER/CONSUMER: thread 0 stores to a slot; threads 1+ load it
 *   3 - READ SHARING:      all threads read the same const cache-line value
 *   4 - NO SHARING:        each thread writes its own cache-line-aligned slot
 *
 * Compile:
 *   gcc -O0 -g -pthread -o false_sharing_benchmark false_sharing_benchmark.c
 *
 * Run:
 *   ./false_sharing_benchmark [threads]          (default 4, minimum 2)
 *
 * Run under PIN:
 *   pin -t cache_sharing_detector.so -- ./false_sharing_benchmark [threads]
 */

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define CACHE_LINE_SIZE    64
#define MAX_THREADS        8
#define DEFAULT_THREADS    4
#define DEFAULT_ITERATIONS 10000000
#define NUM_SCENARIOS      5

/* ------------------------------------------------------------------ *
 * Scenario 0 — TRUE SHARING
 * All threads write the same variable (data race, not false sharing).
 * ------------------------------------------------------------------ */
static volatile uint64_t true_shared;

/* ------------------------------------------------------------------ *
 * Scenario 1 — FALSE SHARING
 * Each thread writes its own uint64 element, but all elements sit on
 * the same cache line (8 × 8 bytes = 64 bytes = 1 cache line).
 * ------------------------------------------------------------------ */
struct FalseSharing {
    volatile uint64_t c[MAX_THREADS];
} __attribute__((aligned(CACHE_LINE_SIZE)));
static struct FalseSharing fs;

/* ------------------------------------------------------------------ *
 * Scenario 2 — PRODUCER / CONSUMER
 * Thread 0 (producer) does write-only stores to pc_slot.value.
 * Threads 1+ (consumers) do read-only loads from pc_slot.value and
 * accumulate into their own cache-line-aligned slots — they never
 * write back to pc_slot's cache line.
 * ------------------------------------------------------------------ */
struct ProdConSlot {
    volatile uint64_t value;
    char pad[CACHE_LINE_SIZE - sizeof(uint64_t)];
} __attribute__((aligned(CACHE_LINE_SIZE)));
static struct ProdConSlot pc_slot;

struct ConsumerSlot {
    uint64_t sum;
    char pad[CACHE_LINE_SIZE - sizeof(uint64_t)];
} __attribute__((aligned(CACHE_LINE_SIZE)));
static struct ConsumerSlot pc_sums[MAX_THREADS];

/* ------------------------------------------------------------------ *
 * Scenario 3 — READ SHARING
 * const global → stored in rodata, never written at runtime.
 * All worker threads read from it; PIN sees reads from N threads and
 * zero writes → read_sharing classification in the detector.
 * ------------------------------------------------------------------ */
struct ReadSlot {
    uint64_t value;
    char pad[CACHE_LINE_SIZE - sizeof(uint64_t)];
} __attribute__((aligned(CACHE_LINE_SIZE)));
static const struct ReadSlot read_slot = { .value = 0xCAFEBABEULL };

struct ReadSum {
    uint64_t val;
    char pad[CACHE_LINE_SIZE - sizeof(uint64_t)];
} __attribute__((aligned(CACHE_LINE_SIZE)));
static struct ReadSum read_sums[MAX_THREADS];

/* ------------------------------------------------------------------ *
 * Scenario 4 — NO SHARING
 * Each thread writes only to its own cache-line-aligned slot.
 * ------------------------------------------------------------------ */
struct PrivateSlot {
    uint64_t val;
    char pad[CACHE_LINE_SIZE - sizeof(uint64_t)];
} __attribute__((aligned(CACHE_LINE_SIZE)));
static struct PrivateSlot private_slots[MAX_THREADS];


/* ================================================================== */
typedef struct {
    int      thread_id;   /* 0-based application index */
    int      scenario;
    uint64_t iterations;
} ThreadArgs;

static void *worker(void *arg) {
    ThreadArgs *a = (ThreadArgs *)arg;
    uint64_t i;

    switch (a->scenario) {

    case 0: /* TRUE SHARING — all threads write the same word */
        for (i = 0; i < a->iterations; i++)
            true_shared++;
        break;

    case 1: /* FALSE SHARING — each thread writes its own word, same cache line */
        for (i = 0; i < a->iterations; i++)
            fs.c[a->thread_id]++;
        break;

    case 2: /* PRODUCER / CONSUMER */
        if (a->thread_id == 0) {
            /* producer: pure store — does NOT read pc_slot */
            for (i = 0; i < a->iterations; i++)
                pc_slot.value = i;
        } else {
            /* consumers: pure load from pc_slot, write only to their own slot */
            for (i = 0; i < a->iterations; i++)
                pc_sums[a->thread_id].sum += pc_slot.value;
        }
        break;

    case 3: /* READ SHARING — all threads load the same const value */
        for (i = 0; i < a->iterations; i++)
            read_sums[a->thread_id].val += read_slot.value;
        break;

    case 4: /* NO SHARING — each thread owns its cache line */
        for (i = 0; i < a->iterations; i++)
            private_slots[a->thread_id].val++;
        break;
    }

    return NULL;
}


static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static void run_scenario(int scenario, int nthreads, uint64_t iterations) {
    static const char *names[NUM_SCENARIOS] = {
        "true sharing (data race)",
        "false sharing",
        "producer/consumer",
        "read sharing",
        "no sharing"
    };

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
            fprintf(stderr, "pthread_create failed (thread %d): %d\n", i, rc);
            exit(1);
        }
    }
    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    double elapsed = now_seconds() - t_start;
    printf("Elapsed: %.3f s  |  Accesses/sec: %.0f M\n\n",
           elapsed,
           (double)(iterations * (uint64_t)nthreads) / elapsed / 1e6);
}

static void print_memory_layout(int nthreads) {
    printf("=== Memory layout ===\n");
    printf("Sc 0  true_shared     : %p\n",
           (void *)&true_shared);
    printf("Sc 1  fs.c[0..%d]     : %p .. %p  (same cache line)\n",
           nthreads - 1, (void *)&fs.c[0], (void *)&fs.c[nthreads - 1]);
    printf("Sc 2  pc_slot.value   : %p  (producer writes)\n",
           (void *)&pc_slot.value);
    printf("Sc 2  pc_sums[1..%d]  : %p .. %p  (consumer private lines)\n",
           nthreads - 1, (void *)&pc_sums[1], (void *)&pc_sums[nthreads - 1]);
    printf("Sc 3  read_slot       : %p  (const/rodata, never written)\n",
           (void *)&read_slot);
    printf("Sc 4  private_slots   : %p .. %p  (separate lines)\n",
           (void *)&private_slots[0], (void *)&private_slots[nthreads - 1]);
    printf("\n");
}

int main(int argc, char *argv[]) {
    int      nthreads   = (argc > 1) ? atoi(argv[1]) : DEFAULT_THREADS;
    uint64_t iterations = DEFAULT_ITERATIONS;

    if (nthreads < 2 || nthreads > MAX_THREADS) {
        fprintf(stderr, "Thread count must be between 2 and %d\n", MAX_THREADS);
        return 1;
    }

    printf("Threads: %d  |  Iterations per thread: %llu\n\n",
           nthreads, (unsigned long long)iterations);

    print_memory_layout(nthreads);

    for (int s = 0; s < NUM_SCENARIOS; s++)
        run_scenario(s, nthreads, iterations);

    return 0;
}
