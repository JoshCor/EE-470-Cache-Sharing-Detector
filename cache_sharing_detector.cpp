#include "pin.H"
#include <iostream>
#include <unordered_map>
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <string>

KNOB<std::string> KnobIpDump(KNOB_MODE_WRITEONCE, "pintool",
    "ipdump", "ip_dump.txt", "path for IP dump file (binary, load base, and hotspot IPs)");

#define CACHE_LINE_SIZE 64
#define CACHE_LINE_MASK (~(ADDRINT)(CACHE_LINE_SIZE - 1))
#define MAX_THREADS 64

// statistical choices to save time
#define WRITE_THRESHOLD_PERCENTAGE 0.02 //percentage threshold for hotspot
#define MAX_TRACKED_IPS 8 //how many instruction pointers to track per cache line per thread (for call stack capture and source lookup later)
#define MAX_FRAMES      5          // call frames captured above each unique IP
//sample rate
KNOB<UINT32> KnobSampleRate(KNOB_MODE_WRITEONCE, "pintool",
    "sample_rate", "1", "record 1-in-N accesses (must be a power of two)");
KNOB<BOOL> KnobFrames(KNOB_MODE_WRITEONCE, "pintool",
    "frames", "1", "capture call stack frames for source lookup (disable with -frames 0 for performance)");

static UINT32 g_sample_mask = 0;  // set in main() to (sample_rate - 1)

struct CacheLineRecord {
    uint64_t reads;
    uint64_t writes;
    uint64_t write_mask;
    uint64_t read_mask;
    uint8_t  write_ip_count;
    uint8_t  read_ip_count;
    uint8_t  _pad[6];
    //new cache line
    ADDRINT  write_ips[MAX_TRACKED_IPS];
    ADDRINT  read_ips[MAX_TRACKED_IPS];
};
struct alignas(CACHE_LINE_SIZE) SampleCounter { uint32_t val = 0; }; //prevents false sharing on the sample counters themselves (each cache line size)
struct ImageInfo { std::string path; ADDRINT load_base; };

static std::unordered_map<ADDRINT, CacheLineRecord> instrumentation_records[MAX_THREADS];
static SampleCounter g_sample_ctr[MAX_THREADS];
static std::vector<ImageInfo> g_images;
struct FrameStack { ADDRINT f[MAX_FRAMES]; };
// Per-thread: IP -> return addresses walking up from RBP at first-seen site
static std::unordered_map<ADDRINT, FrameStack> g_ip_frames[MAX_THREADS];

//load file and base address into vector for later use in source lookup with libdwfl
VOID ImageLoad(IMG img, VOID* v) {
    g_images.push_back({IMG_Name(img), IMG_LowAddress(img)});
}

// Walk frame pointers from rbp to collect up to MAX_FRAMES return addresses.
// Only runs once per unique (tid, ip) pair — amortized to nothing on the hot path.
static VOID capture_frames(ADDRINT ip, ADDRINT rbp, THREADID tid) {
    if (g_ip_frames[tid].count(ip)) return;
    FrameStack fs = {};
    ADDRINT cur = rbp;
    for (int i = 0; i < MAX_FRAMES; i++) {
        if (!cur) break;
        ADDRINT ret = 0, next = 0;
        if (PIN_SafeCopy(&ret,  (VOID*)(cur + sizeof(ADDRINT)), sizeof(ADDRINT)) != sizeof(ADDRINT)) break;
        if (PIN_SafeCopy(&next, (VOID*)cur,                    sizeof(ADDRINT)) != sizeof(ADDRINT)) break;
        if (!next || next <= cur) break;  // stack grows down; sanity guard
        fs.f[i] = ret;
        cur = next;
    }
    g_ip_frames[tid].emplace(ip, fs);
}

//collect data if write operation and no stack frame data
VOID RecordWrite(VOID* addr, THREADID tid) {
    if (g_sample_ctr[tid].val++ & g_sample_mask) return;
    ADDRINT mem_addr   = (ADDRINT)addr;
    ADDRINT cache_line = mem_addr & CACHE_LINE_MASK;
    CacheLineRecord& rec = instrumentation_records[tid].try_emplace(cache_line).first->second;
    rec.writes++;
    rec.write_mask |= (1ULL << (mem_addr & (CACHE_LINE_SIZE - 1)));
}

VOID RecordWriteFrames(VOID* addr, ADDRINT ip, ADDRINT rbp, THREADID tid) {
    if (g_sample_ctr[tid].val++ & g_sample_mask) return;
    ADDRINT mem_addr   = (ADDRINT)addr;
    ADDRINT cache_line = mem_addr & CACHE_LINE_MASK;
    CacheLineRecord& rec = instrumentation_records[tid].try_emplace(cache_line).first->second;
    rec.writes++;
    rec.write_mask |= (1ULL << (mem_addr & (CACHE_LINE_SIZE - 1)));
    if (rec.write_ip_count < MAX_TRACKED_IPS) {
        for (uint8_t i = 0; i < rec.write_ip_count; i++)
            if (rec.write_ips[i] == ip) return;
        rec.write_ips[rec.write_ip_count++] = ip;
        capture_frames(ip, rbp, tid);
    }
}

//collect data if read operation
VOID RecordRead(VOID* addr, THREADID tid) {
    if (g_sample_ctr[tid].val++ & g_sample_mask) return;
    ADDRINT mem_addr   = (ADDRINT)addr;
    ADDRINT cache_line = mem_addr & CACHE_LINE_MASK;
    CacheLineRecord& rec = instrumentation_records[tid].try_emplace(cache_line).first->second;
    rec.reads++;
    rec.read_mask |= (1ULL << (mem_addr & (CACHE_LINE_SIZE - 1)));
}

VOID RecordReadFrames(VOID* addr, ADDRINT ip, ADDRINT rbp, THREADID tid) {
    if (g_sample_ctr[tid].val++ & g_sample_mask) return;
    ADDRINT mem_addr   = (ADDRINT)addr;
    ADDRINT cache_line = mem_addr & CACHE_LINE_MASK;
    CacheLineRecord& rec = instrumentation_records[tid].try_emplace(cache_line).first->second;
    rec.reads++;
    rec.read_mask |= (1ULL << (mem_addr & (CACHE_LINE_SIZE - 1)));
    if (rec.read_ip_count < MAX_TRACKED_IPS) {
        for (uint8_t i = 0; i < rec.read_ip_count; i++)
            if (rec.read_ips[i] == ip) return;
        rec.read_ips[rec.read_ip_count++] = ip;
        capture_frames(ip, rbp, tid);
    }
}

//pass instruction data to correct method
VOID Instruction(INS ins, VOID* v) {
    bool frames = KnobFrames.Value();
    if (INS_IsMemoryWrite(ins)) {
        if (frames)
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordWriteFrames,
                IARG_MEMORYWRITE_EA, IARG_INST_PTR, IARG_REG_VALUE, LEVEL_BASE::REG_RBP, IARG_THREAD_ID, IARG_END);
        else
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordWrite,
                IARG_MEMORYWRITE_EA, IARG_THREAD_ID, IARG_END);
    }
    if (INS_IsMemoryRead(ins)) {
        if (frames)
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordReadFrames,
                IARG_MEMORYREAD_EA, IARG_INST_PTR, IARG_REG_VALUE, LEVEL_BASE::REG_RBP, IARG_THREAD_ID, IARG_END);
        else
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordRead,
                IARG_MEMORYREAD_EA, IARG_THREAD_ID, IARG_END);
    }
    if (INS_HasMemoryRead2(ins)) {
        if (frames)
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordReadFrames,
                IARG_MEMORYREAD2_EA, IARG_INST_PTR, IARG_REG_VALUE, LEVEL_BASE::REG_RBP, IARG_THREAD_ID, IARG_END);
        else
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordRead,
                IARG_MEMORYREAD2_EA, IARG_THREAD_ID, IARG_END);
    }
}

//do analysis on collected data and print results at the end of the program execution
VOID Fini(INT32 code, VOID* v) {
    std::map<ADDRINT, std::map<int, const CacheLineRecord*>> by_line;
    uint64_t total_writes = 0; //sum all writes for reporting
    uint64_t total_reads = 0; //sum all reads for reporting

    //make a new inverted structure: lines -> threads -> records
    for (int t = 0; t < MAX_THREADS; t++) {
        for (auto& [cache_line, rec] : instrumentation_records[t]) {
            by_line[cache_line][t] = &rec;
            total_writes += rec.writes;
            total_reads += rec.reads;
        }
    }

    //define hotspot (false, true, producer-consumer, read-sharing) then set threshold for hotspot
    struct Hotspot {
        ADDRINT  cache_line;
        uint64_t line_writes;
        bool     has_false_sharing;
        bool     has_true_sharing;
        bool     has_producer_consumer;
        bool     has_read_sharing;
        std::map<int, const CacheLineRecord*> threads;
    };
    std::vector<Hotspot> hotspots;
    uint64_t threshold = total_writes / (100 / WRITE_THRESHOLD_PERCENTAGE); // 0.1%

    //look through the map and make hotspot list
    for (auto& [cache_line, thread_to_record_map] : by_line) {
        if (thread_to_record_map.size() < 2) continue; // skip this cache line (only 1 thread)

        //count writes and reads
        uint64_t line_writes = 0;
        uint64_t line_reads  = 0;
        for (auto& [tid, rec] : thread_to_record_map) {
            line_writes += rec->writes;
            line_reads  += rec->reads;
        }
        uint64_t read_threshold = total_reads / (uint64_t)(100.0 / WRITE_THRESHOLD_PERCENTAGE);
        if (line_writes <= threshold && line_reads <= read_threshold) continue;

        //count sharing based on masks
        uint8_t write_bit_count[64] = {};
        uint8_t read_bit_count[64]  = {};
        uint8_t addr_bit_count[64]  = {};
        for (auto& [tid, rec] : thread_to_record_map) {
            for (int b = 0; b < 64; b++) {
                if (rec->write_mask & (1ULL << b))                    write_bit_count[b]++;
                if (rec->read_mask  & (1ULL << b))                    read_bit_count[b]++;
                if ((rec->write_mask | rec->read_mask) & (1ULL << b)) addr_bit_count[b]++;
            }
        }

        //=========================================================
        //define what we are profiling here based on collected data:
        //=========================================================
        bool has_false_sharing     = false;
        bool has_true_sharing      = false;
        bool has_producer_consumer = false;
        bool has_read_sharing      = false;
        for (int b = 0; b < 64; b++) {
            if (write_bit_count[b] >= 2) has_true_sharing = true;
            if (write_bit_count[b] == 0 && addr_bit_count[b] >= 2) has_read_sharing = true;
            if (write_bit_count[b] == 1)
                for (auto& [tid, rec] : thread_to_record_map)
                    if ((rec->read_mask & (1ULL << b)) && !(rec->write_mask & (1ULL << b)))
                        has_producer_consumer = true;
        }
        int exclusive_writers = 0;
        for (auto& [tid, rec] : thread_to_record_map) {
            for (int b = 0; b < 64; b++) {
                if ((rec->write_mask & (1ULL << b)) && write_bit_count[b] == 1) {
                    exclusive_writers++;
                    break;
                }
            }
        }
        has_false_sharing = (exclusive_writers >= 2);

        hotspots.push_back({cache_line, line_writes, has_false_sharing, has_true_sharing,
                            has_producer_consumer, has_read_sharing, thread_to_record_map});
    }

    // sort biggest to smallest hotspots (interesting code)
    std::sort(hotspots.begin(), hotspots.end(),
        [](const Hotspot& a, const Hotspot& b) {
            return a.line_writes > b.line_writes;
        });

    //print results
    std::cerr << "\n[detector] false sharing report\n";
    std::cerr << "=========================================\n";

    int rank = 0;
    for (auto& hs : hotspots) {
        rank++;
        //construct label
        std::string label;
        if (hs.has_true_sharing)      { label += "TRUE SHARING"; }
        if (hs.has_false_sharing)     { if (!label.empty()) label += " + "; label += "FALSE SHARING"; }
        if (hs.has_producer_consumer) { if (!label.empty()) label += " + "; label += "PRODUCER-CONSUMER"; }
        if (hs.has_read_sharing)      { if (!label.empty()) label += " + "; label += "READ SHARING"; }
        if (label.empty())            { label = "UNKNOWN"; }
        //print message
        std::cerr << "\nHotspot " << rank
                  << " [" << label << "]"
                  << ": cache line 0x" << std::hex << hs.cache_line << std::dec << "\n";
        std::cerr << "  total writes: " << hs.line_writes << "\n";
        std::cerr << "  threads: " << hs.threads.size() << "\n";
        //print some totals
        for (auto& [tid, rec] : hs.threads) {
            std::cerr << "    thread " << tid
                      << ": " << rec->writes << " writes, "
                      << rec->reads  << " reads\n";
            // per-byte access map: B=read+write W=write-only R=read-only .=none
            // grouped into 8-byte blocks matching a cache line's natural structure
            std::cerr << "      ";
            for (int b = 0; b < 64; b++) {
                if (b > 0 && b % 8 == 0) std::cerr << ' ';
                bool w = (rec->write_mask >> b) & 1;
                bool r = (rec->read_mask  >> b) & 1;
                std::cerr << (w && r ? 'B' : w ? 'W' : r ? 'R' : '.');
            }
            std::cerr << "\n";
        }
    }

    if (rank == 0)
        std::cerr << "no hotspots detected above threshold\n";

    std::cerr << "=========================================\n";
    std::cerr << "[detector] done. total writes observed: " << total_writes << "\n";
    std::cerr << "[detector] done. total reads observed: " << total_reads << "\n";

    //=========================================================
    //SEND OFF DATA FOR SOURCE LOOKUP
    //=========================================================
    // write IP dump for source_lookup to resolve IPs -> file:line via DWARF and source_lookup.cpp
    FILE* dump = fopen(KnobIpDump.Value().c_str(), "w");
    if (dump) {
        for (auto& img : g_images)
            fprintf(dump, "image:%s:0x%lx\n", img.path.c_str(), (unsigned long)img.load_base);
        for (auto& hs : hotspots) {
            for (auto& [tid, rec] : hs.threads) {
                for (uint8_t i = 0; i < rec->write_ip_count; i++) {
                    fprintf(dump, "write %d 0x%lx", tid, (unsigned long)rec->write_ips[i]);
                    auto it = g_ip_frames[tid].find(rec->write_ips[i]);
                    if (it != g_ip_frames[tid].end())
                        for (int fi = 0; fi < MAX_FRAMES; fi++)
                            if (it->second.f[fi]) fprintf(dump, " 0x%lx", (unsigned long)it->second.f[fi]);
                    fprintf(dump, "\n");
                }
                for (uint8_t i = 0; i < rec->read_ip_count; i++) {
                    fprintf(dump, "read %d 0x%lx", tid, (unsigned long)rec->read_ips[i]);
                    auto it = g_ip_frames[tid].find(rec->read_ips[i]);
                    if (it != g_ip_frames[tid].end())
                        for (int fi = 0; fi < MAX_FRAMES; fi++)
                            if (it->second.f[fi]) fprintf(dump, " 0x%lx", (unsigned long)it->second.f[fi]);
                    fprintf(dump, "\n");
                }
            }
        }
        fclose(dump);
        std::cerr << "[detector] IP dump written to: " << KnobIpDump.Value() << "\n";
    } else {
        std::cerr << "[detector] warning: could not open IP dump file: " << KnobIpDump.Value() << "\n";
    }

    // write stats CSV alongside the ipdump (replace -ips.txt suffix)
    std::string stats_path = KnobIpDump.Value();
    size_t sfx = stats_path.rfind("-ips.txt");
    if (sfx != std::string::npos) stats_path.replace(sfx, 8, "-stats.csv");
    else                          stats_path += "-stats.csv";

    FILE* stats = fopen(stats_path.c_str(), "w");
    if (stats) {
        fprintf(stats, "rank,sharing,hotspot_writes,tid,writes,reads,write_mask,read_mask,sample_rate\n");
        int r = 0;
        for (auto& hs : hotspots) {
            r++;
            std::string sharing;
            if (hs.has_true_sharing)      { sharing += "true_sharing"; }
            if (hs.has_false_sharing)     { if (!sharing.empty()) sharing += "|"; sharing += "false_sharing"; }
            if (hs.has_producer_consumer) { if (!sharing.empty()) sharing += "|"; sharing += "producer_consumer"; }
            if (hs.has_read_sharing)      { if (!sharing.empty()) sharing += "|"; sharing += "read_sharing"; }
            for (auto& [tid, rec] : hs.threads) {
                fprintf(stats, "%d,%s,%lu,%d,%lu,%lu,0x%016lx,0x%016lx,%u\n",
                    r, sharing.c_str(),
                    (unsigned long)hs.line_writes,
                    tid,
                    (unsigned long)rec->writes,
                    (unsigned long)rec->reads,
                    (unsigned long)rec->write_mask,
                    (unsigned long)rec->read_mask,
                    (unsigned)KnobSampleRate.Value());
            }
        }
        fclose(stats);
        std::cerr << "[detector] stats written to: " << stats_path << "\n";
    }
}

int main(int argc, char* argv[]) {
    PIN_InitSymbols();
    PIN_Init(argc, argv);
    g_sample_mask = KnobSampleRate.Value() - 1;
    IMG_AddInstrumentFunction(ImageLoad, nullptr);
    INS_AddInstrumentFunction(Instruction, nullptr);
    PIN_AddFiniFunction(Fini, nullptr);
    PIN_StartProgram();
    return 0;
}
