#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <map>
#include <string>
#include <vector>
#include <algorithm>
#include <elfutils/libdwfl.h>
#include <elfutils/libdw.h>
#include <dwarf.h>

// Reads an IP dump file produced by cache_sharing_detector and summarises
// all resolved source locations, deduplicating by file:line.
//
// Usage: ./source_lookup <ip_dump_file>

struct HitInfo {
    int      count       = 0;
    uint64_t thread_mask = 0;
    bool     has_write   = false;
    bool     has_read    = false;
};

static std::map<std::string, HitInfo> g_hits;
static char g_source_prefix[4096] = "";  // dirname of the instrumented binary

static void add_hit(const char* file, int line, int tid, bool is_write) {
    if (!file || line <= 0) return;
    if (g_source_prefix[0] && strncmp(file, g_source_prefix, strlen(g_source_prefix)) != 0) return;
    char key[2048];
    snprintf(key, sizeof(key), "%s:%d", file, line);
    HitInfo& h = g_hits[key];
    h.count++;
    h.thread_mask |= (1ULL << tid);
    if (is_write) h.has_write = true; else h.has_read = true;
}

// Print ±10 lines of source around lineno, marking the hot line with an arrow.
static void print_source_context(const char* filepath, int lineno) {
    FILE* f = fopen(filepath, "r");
    if (!f) return;

    int start = (lineno > 10) ? lineno - 10 : 1;
    int end   = lineno + 10;
    char buf[4096];
    int cur = 0;

    while (fgets(buf, sizeof(buf), f)) {
        cur++;
        if (cur < start) continue;
        if (cur > end)   break;
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';
        if (cur == lineno)
            printf("  \033[1;33m->%4d\033[0m  %s\n", cur, buf);
        else
            printf("    %4d  %s\n", cur, buf);
    }
    fclose(f);
}

static void collect_inline_chain(Dwfl *dwfl, Dwarf_Addr ip, int tid, bool is_write) {
    Dwfl_Module *mod = dwfl_addrmodule(dwfl, ip);
    if (!mod) return;
    Dwarf_Addr bias = 0;
    Dwarf *dwarf = dwfl_module_getdwarf(mod, &bias);
    if (!dwarf) return;
    Dwarf_Die cudie;
    if (!dwarf_addrdie(dwarf, ip - bias, &cudie)) return;
    Dwarf_Die *scopes = NULL;
    int n = dwarf_getscopes(&cudie, ip - bias, &scopes);
    if (n <= 0) return;
    for (int i = 0; i < n; i++) {
        if (dwarf_tag(&scopes[i]) != DW_TAG_inlined_subroutine) continue;
        Dwarf_Word file_idx = 0, line_no = 0;
        Dwarf_Attribute attr;
        if (dwarf_attr(&scopes[i], DW_AT_call_file, &attr))
            dwarf_formudata(&attr, &file_idx);
        if (dwarf_attr(&scopes[i], DW_AT_call_line, &attr))
            dwarf_formudata(&attr, &line_no);
        Dwarf_Files *files = NULL;
        size_t nfiles = 0;
        const char *call_file = NULL;
        if (dwarf_getsrcfiles(&cudie, &files, &nfiles) == 0 && file_idx < nfiles)
            call_file = dwarf_filesrc(files, file_idx, NULL, NULL);
        add_hit(call_file, (int)line_no, tid, is_write);
    }
    free(scopes);
}

static void collect_ip(Dwfl *dwfl, Dwarf_Addr ip, int tid, bool is_write) {
    Dwfl_Line *fl = dwfl_getsrc(dwfl, ip);
    if (!fl) return;
    int lineno, col;
    const char *file = dwfl_lineinfo(fl, NULL, &lineno, &col, NULL, NULL);
    add_hit(file, lineno, tid, is_write);
    collect_inline_chain(dwfl, ip, tid, is_write);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <ip_dump_file>\n", argv[0]);
        return 1;
    }

    FILE* fp = fopen(argv[1], "r");
    if (!fp) { perror("fopen"); return 1; }

    static const Dwfl_Callbacks callbacks = {
        .find_elf       = dwfl_build_id_find_elf,
        .find_debuginfo = dwfl_standard_find_debuginfo,
    };
    Dwfl* dwfl = dwfl_begin(&callbacks);
    dwfl_report_begin(dwfl);

    char line[4096];
    GElf_Addr first_image_base = 0;
    bool first_image = true;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "image:", 6) != 0) break;
        char* last_colon = strrchr(line, ':');
        if (!last_colon) continue;
        unsigned long load_base = 0;
        sscanf(last_colon + 1, "%lx", &load_base);
        *last_colon = '\0';
        const char* path = line + 6;
        if (first_image) {
            first_image_base = (GElf_Addr)load_base;
            first_image = false;
        }
        dwfl_report_elf(dwfl, path, path, -1, (GElf_Addr)load_base, false);
    }
    dwfl_report_end(dwfl, NULL, NULL);

    // derive source prefix from the binary's DWARF DW_AT_comp_dir — works regardless
    // of where the binary file itself lives
    if (first_image_base) {
        Dwfl_Module *binary_mod = dwfl_addrmodule(dwfl, first_image_base);
        if (binary_mod) {
            Dwarf_Addr bias = 0;
            Dwarf *dwarf = dwfl_module_getdwarf(binary_mod, &bias);
            if (dwarf) {
                Dwarf_Off off = 0, next_off;
                size_t hdr;
                while (dwarf_nextcu(dwarf, off, &next_off, &hdr, NULL, NULL, NULL) == 0) {
                    Dwarf_Die cudie;
                    if (dwarf_offdie(dwarf, off + hdr, &cudie)) {
                        Dwarf_Attribute attr;
                        if (dwarf_attr(&cudie, DW_AT_comp_dir, &attr)) {
                            const char *comp_dir = dwarf_formstring(&attr);
                            if (comp_dir && comp_dir[0]) {
                                strncpy(g_source_prefix, comp_dir, sizeof(g_source_prefix) - 1);
                                break;
                            }
                        }
                    }
                    off = next_off;
                }
            }
        }
    }

    do {
        char type[8];
        int tid;
        unsigned long ip;
        if (sscanf(line, "%7s %d %lx", type, &tid, &ip) != 3) continue;
        bool is_write = (strncmp(type, "write", 5) == 0);

        collect_ip(dwfl, (Dwarf_Addr)ip, tid, is_write);

        // advance past "type tid ip" and parse any frame addresses
        char *p = line;
        for (int skip = 3; skip > 0; skip--) {
            while (*p && !isspace((unsigned char)*p)) p++;
            while (*p && isspace((unsigned char)*p)) p++;
        }
        while (*p && *p != '\n') {
            char *end;
            unsigned long faddr = strtoul(p, &end, 0);
            if (end == p) break;
            p = end;
            collect_ip(dwfl, (Dwarf_Addr)faddr, tid, is_write);
        }
    } while (fgets(line, sizeof(line), fp));

    fclose(fp);
    dwfl_end(dwfl);

    // sort by hit count descending
    std::vector<std::pair<std::string, HitInfo>> sorted(g_hits.begin(), g_hits.end());
    std::sort(sorted.begin(), sorted.end(),
        [](const std::pair<std::string, HitInfo>& a,
           const std::pair<std::string, HitInfo>& b) {
            return a.second.count > b.second.count;
        });

    printf("unique source locations from: %s\n", argv[1]);
    printf("filtering to: %s/\n\n", g_source_prefix);
    printf("%-6s  %-5s  %-14s  %s\n", "hits", "r/w", "threads", "location");
    printf("%-6s  %-5s  %-14s  %s\n", "------", "-----", "--------------", "--------");

    for (size_t i = 0; i < sorted.size(); i++) {
        const std::string& loc  = sorted[i].first;
        const HitInfo&     h    = sorted[i].second;

        // build compact thread list
        char threads[64] = "";
        bool first = true;
        for (int t = 0; t < 64; t++) {
            if (!(h.thread_mask & (1ULL << t))) continue;
            if (!first) strncat(threads, ",", sizeof(threads) - strlen(threads) - 1);
            char tmp[8];
            snprintf(tmp, sizeof(tmp), "%d", t);
            strncat(threads, tmp, sizeof(threads) - strlen(threads) - 1);
            first = false;
        }

        const char* rw = (h.has_write && h.has_read) ? "rw"
                       : h.has_write                 ? "write"
                                                     : "read";
        printf("%-6d  %-5s  %-14s  %s\n", h.count, rw, threads, loc.c_str());
    }

    // --- source context for each hit location ---
    printf("\n\033[1m=== source context ===\033[0m\n");
    for (size_t i = 0; i < sorted.size(); i++) {
        const std::string& loc = sorted[i].first;
        const HitInfo&     h   = sorted[i].second;

        // parse "filepath:lineno" from the key
        size_t colon = loc.rfind(':');
        if (colon == std::string::npos) continue;
        std::string filepath = loc.substr(0, colon);
        int lineno = std::stoi(loc.substr(colon + 1));

        // build thread list for the header
        char threads[64] = "";
        bool first = true;
        for (int t = 0; t < 64; t++) {
            if (!(h.thread_mask & (1ULL << t))) continue;
            if (!first) strncat(threads, ",", sizeof(threads) - strlen(threads) - 1);
            char tmp[8];
            snprintf(tmp, sizeof(tmp), "%d", t);
            strncat(threads, tmp, sizeof(threads) - strlen(threads) - 1);
            first = false;
        }
        const char* rw = (h.has_write && h.has_read) ? "rw"
                       : h.has_write                 ? "write"
                                                     : "read";
        printf("\n\033[1m%s\033[0m  [%d hits, %s, threads %s]\n",
               loc.c_str(), h.count, rw, threads);
        print_source_context(filepath.c_str(), lineno);
    }

    return 0;
}
