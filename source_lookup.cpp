#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elfutils/libdwfl.h>

// Reads an IP dump file produced by cache_sharing_detector and resolves each
// instruction pointer to a source file:line using DWARF debug info via libdwfl.
//
// Usage: ./source_lookup <ip_dump_file>
//
// ip_dump format (written by the Pin tool):
//   binary:/path/to/binary
//   load_base:0x<hex>
//   write <tid> 0x<hex ip>
//   read  <tid> 0x<hex ip>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <ip_dump_file>\n", argv[0]);
        return 1;
    }

    FILE* fp = fopen(argv[1], "r");
    if (!fp) { perror("fopen"); return 1; }

    // --- parse header ---
    char binary_path[4096] = {};
    unsigned long load_base = 0;

    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "binary:", 7) == 0) {
            line[strcspn(line, "\n")] = '\0';
            strncpy(binary_path, line + 7, sizeof(binary_path) - 1);
        } else if (strncmp(line, "load_base:", 10) == 0) {
            sscanf(line + 10, "%lx", &load_base);
            break; // header is done, IPs follow
        }
    }

    if (binary_path[0] == '\0') {
        fprintf(stderr, "error: no binary path in dump file\n");
        return 1;
    }

    // --- init libdwfl ---
    // dwfl_report_elf takes a 'base' bias: the amount added to file addresses
    // to produce runtime addresses. For PIE binaries this equals the load base.
    static const Dwfl_Callbacks callbacks = {
        .find_elf       = dwfl_build_id_find_elf,
        .find_debuginfo = dwfl_standard_find_debuginfo,
    };
    Dwfl* dwfl = dwfl_begin(&callbacks);
    dwfl_report_begin(dwfl);
    Dwfl_Module* mod = dwfl_report_elf(dwfl, "main", binary_path, -1,
                                       (GElf_Addr)load_base, false);
    if (!mod) {
        fprintf(stderr, "dwfl_report_elf failed: %s\n", dwfl_errmsg(-1));
        return 1;
    }
    dwfl_report_end(dwfl, NULL, NULL);

    // --- resolve IPs ---
    printf("source locations from: %s\n\n", argv[1]);

    while (fgets(line, sizeof(line), fp)) {
        char type[8];
        int tid;
        unsigned long ip;
        if (sscanf(line, "%7s %d %lx", type, &tid, &ip) != 3) continue;

        Dwfl_Line* dwfl_line = dwfl_getsrc(dwfl, (Dwarf_Addr)ip);
        if (dwfl_line) {
            int lineno, col;
            const char* filename = dwfl_lineinfo(dwfl_line, NULL, &lineno, &col, NULL, NULL);
            printf("thread %d  %-5s  0x%lx  ->  %s:%d\n",
                   tid, type, ip, filename ? filename : "(unknown)", lineno);
        } else {
            printf("thread %d  %-5s  0x%lx  ->  (no debug info)\n", tid, type, ip);
        }
    }

    fclose(fp);
    dwfl_end(dwfl);
    return 0;
}
