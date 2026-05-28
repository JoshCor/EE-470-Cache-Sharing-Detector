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
#define WRITE_THRESHOLD_PERCENTAGE 0.1 //percentage threshold for hotspot 

#define MAX_TRACKED_IPS 8

struct CacheLineRecord {
    uint64_t reads;
    uint64_t writes;
    uint64_t write_mask;
    uint64_t read_mask;
    ADDRINT  write_ips[MAX_TRACKED_IPS];
    ADDRINT  read_ips[MAX_TRACKED_IPS];
    uint8_t  write_ip_count;
    uint8_t  read_ip_count;
};

static std::unordered_map<ADDRINT, CacheLineRecord> instrumentation_records[MAX_THREADS];

struct ImageInfo { std::string path; ADDRINT load_base; };
static std::vector<ImageInfo> g_images;

VOID ImageLoad(IMG img, VOID* v) {
    g_images.push_back({IMG_Name(img), IMG_LowAddress(img)});
}

// get data on a given memory access and store it in the larger datastructure
VOID RecordAccess(VOID* addr, BOOL is_write, ADDRINT ip, THREADID tid) {
    ADDRINT mem_addr          = (ADDRINT)addr;
    ADDRINT cache_line = mem_addr & CACHE_LINE_MASK;

    CacheLineRecord& rec = instrumentation_records[tid].try_emplace(cache_line).first->second;

    rec.reads  += is_write ? 0 : 1;
    rec.writes += is_write ? 1 : 0;
    if (is_write)
        rec.write_mask |= (1ULL << (mem_addr & (CACHE_LINE_SIZE - 1)));
    else
        rec.read_mask  |= (1ULL << (mem_addr & (CACHE_LINE_SIZE - 1)));

    //store instructon pointers in a list for up to MAX_TRACKED_IPS unique IPs
    if (is_write && rec.write_ip_count < MAX_TRACKED_IPS) {
        bool found = false;
        for (uint8_t i = 0; i < rec.write_ip_count; i++)
            if (rec.write_ips[i] == ip) { found = true; break; }
        if (!found)
            rec.write_ips[rec.write_ip_count++] = ip;
    } else if (!is_write && rec.read_ip_count < MAX_TRACKED_IPS) {
        bool found = false;
        for (uint8_t i = 0; i < rec.read_ip_count; i++)
            if (rec.read_ips[i] == ip) { found = true; break; }
        if (!found)
            rec.read_ips[rec.read_ip_count++] = ip;
    }
}

VOID Instruction(INS ins, VOID* v) {
    if (INS_IsMemoryWrite(ins)) {
        INS_InsertPredicatedCall(
            ins,
            IPOINT_BEFORE,
            (AFUNPTR)RecordAccess,
            IARG_MEMORYWRITE_EA,
            IARG_BOOL, TRUE,
            IARG_INST_PTR,
            IARG_THREAD_ID,
            IARG_END
        );
    }

    if (INS_IsMemoryRead(ins)) {
        INS_InsertPredicatedCall(
            ins,
            IPOINT_BEFORE,
            (AFUNPTR)RecordAccess,
            IARG_MEMORYREAD_EA,
            IARG_BOOL, FALSE,
            IARG_INST_PTR,
            IARG_THREAD_ID,
            IARG_END
        );
    }

    if (INS_HasMemoryRead2(ins)) {
        INS_InsertPredicatedCall(
            ins,
            IPOINT_BEFORE,
            (AFUNPTR)RecordAccess,
            IARG_MEMORYREAD2_EA,
            IARG_BOOL, FALSE,
            IARG_INST_PTR,
            IARG_THREAD_ID,
            IARG_END
        );
    }
}



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

        //count writes
        uint64_t line_writes = 0;
        for (auto& [tid, rec] : thread_to_record_map) //rec is a pointer to record
            line_writes += rec->writes;
        if (line_writes <= threshold) continue; //if total writes is less than threshold continue

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
            if (write_bit_count[b] == 1) has_false_sharing = true;
            if (write_bit_count[b] == 0 && addr_bit_count[b] >= 2) has_read_sharing = true;
            if (write_bit_count[b] == 1)
                for (auto& [tid, rec] : thread_to_record_map)
                    if ((rec->read_mask & (1ULL << b)) && !(rec->write_mask & (1ULL << b)))
                        has_producer_consumer = true;
        }

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
        }
    }

    if (rank == 0)
        std::cerr << "no hotspots detected above threshold\n";

    std::cerr << "=========================================\n";
    std::cerr << "[detector] done. total writes observed: " << total_writes << "\n";
    std::cerr << "[detector] done. total reads observed: " << total_reads << "\n";

    // write IP dump for source_lookup to resolve IPs -> file:line via DWARF
    FILE* dump = fopen(KnobIpDump.Value().c_str(), "w");
    if (dump) {
        for (auto& img : g_images)
            fprintf(dump, "image:%s:0x%lx\n", img.path.c_str(), (unsigned long)img.load_base);
        for (auto& hs : hotspots) {
            for (auto& [tid, rec] : hs.threads) {
                for (uint8_t i = 0; i < rec->write_ip_count; i++)
                    fprintf(dump, "write %d 0x%lx\n", tid, (unsigned long)rec->write_ips[i]);
                for (uint8_t i = 0; i < rec->read_ip_count; i++)
                    fprintf(dump, "read %d 0x%lx\n", tid, (unsigned long)rec->read_ips[i]);
            }
        }
        fclose(dump);
        std::cerr << "[detector] IP dump written to: " << KnobIpDump.Value() << "\n";
    } else {
        std::cerr << "[detector] warning: could not open IP dump file: " << KnobIpDump.Value() << "\n";
    }
}

int main(int argc, char* argv[]) {
    PIN_InitSymbols();
    PIN_Init(argc, argv);
    IMG_AddInstrumentFunction(ImageLoad, nullptr);
    INS_AddInstrumentFunction(Instruction, nullptr);
    PIN_AddFiniFunction(Fini, nullptr);
    PIN_StartProgram();
    return 0;
}
