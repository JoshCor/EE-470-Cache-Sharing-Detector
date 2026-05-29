#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <elfutils/libdwfl.h>
#include <elfutils/libdw.h>
#include <dwarf.h>

// Reads an IP dump file produced by cache_sharing_detector and resolves each
// instruction pointer to a source file:line using DWARF debug info via libdwfl.
// Also walks inlined subroutine chains so compressed call sites are fully visible.
//
// Usage: ./source_lookup <ip_dump_file>
//
// ip_dump format (written by the Pin tool):
//   image:/path/to/binary:0x<load_base>     (one per loaded image)
//   write <tid> 0x<hex ip>
//   read  <tid> 0x<hex ip>

// Walk DW_TAG_inlined_subroutine scopes at 'ip' and print the call chain.
// Each inlined frame records the call site (file:line) where it was inlined.
static void print_inline_chain(Dwfl *dwfl, Dwarf_Addr ip) {
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

        // name lives on the abstract origin DIE, not the inlined instance
        const char *fname = "(unknown)";
        Dwarf_Attribute attr;
        Dwarf_Die origin;
        if (dwarf_attr(&scopes[i], DW_AT_abstract_origin, &attr) &&
            dwarf_formref_die(&attr, &origin))
            fname = dwarf_diename(&origin);

        // call site: file index + line number recorded by the compiler
        Dwarf_Word file_idx = 0, line_no = 0;
        if (dwarf_attr(&scopes[i], DW_AT_call_file, &attr))
            dwarf_formudata(&attr, &file_idx);
        if (dwarf_attr(&scopes[i], DW_AT_call_line, &attr))
            dwarf_formudata(&attr, &line_no);

        // resolve file index through the CU's file table
        Dwarf_Files *files = NULL;
        size_t nfiles = 0;
        const char *call_file = "(unknown)";
        if (dwarf_getsrcfiles(&cudie, &files, &nfiles) == 0 && file_idx < nfiles)
            call_file = dwarf_filesrc(files, file_idx, NULL, NULL);

        printf("    ^ inlined from %s() at %s:%lu\n",
               fname, call_file ? call_file : "(unknown)", (unsigned long)line_no);
    }

    free(scopes);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <ip_dump_file>\n", argv[0]);
        return 1;
    }

    FILE* fp = fopen(argv[1], "r");
    if (!fp) { perror("fopen"); return 1; }

    // --- init libdwfl ---
    static const Dwfl_Callbacks callbacks = {
        .find_elf       = dwfl_build_id_find_elf,
        .find_debuginfo = dwfl_standard_find_debuginfo,
    };
    Dwfl* dwfl = dwfl_begin(&callbacks);
    dwfl_report_begin(dwfl);

    // --- parse header: register all images with dwfl ---
    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "image:", 6) != 0) break;

        char* last_colon = strrchr(line, ':');
        if (!last_colon) continue;

        unsigned long load_base = 0;
        sscanf(last_colon + 1, "%lx", &load_base);
        *last_colon = '\0';
        const char* path = line + 6;

        dwfl_report_elf(dwfl, path, path, -1, (GElf_Addr)load_base, false);
    }
    dwfl_report_end(dwfl, NULL, NULL);

    // --- resolve IPs ---
    printf("source locations from: %s\n\n", argv[1]);

    do {
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
            print_inline_chain(dwfl, (Dwarf_Addr)ip);
        } else {
            Dwfl_Module* mod = dwfl_addrmodule(dwfl, (Dwarf_Addr)ip);
            const char* sym = mod ? dwfl_module_addrname(mod, (Dwarf_Addr)ip) : nullptr;
            printf("thread %d  %-5s  0x%lx  ->  (no src - near symbol: %s)\n",
                   tid, type, ip, sym ? sym : "unknown");
        }

        // parse and resolve any frame addresses after the IP on the same line
        // format: "type tid 0xIP [0xF1 0xF2 ...]"
        char *p = line;
        for (int skip = 3; skip > 0; skip--) {              // skip type, tid, ip tokens
            while (*p && !isspace((unsigned char)*p)) p++;
            while (*p && isspace((unsigned char)*p)) p++;
        }
        int frame_num = 1;
        while (*p && *p != '\n') {
            char *end;
            unsigned long faddr = strtoul(p, &end, 0);
            if (end == p) break;
            p = end;

            Dwfl_Line* fl = dwfl_getsrc(dwfl, (Dwarf_Addr)faddr);
            if (fl) {
                int ln, col;
                const char* fn = dwfl_lineinfo(fl, NULL, &ln, &col, NULL, NULL);
                printf("    frame %d: 0x%lx  ->  %s:%d\n",
                       frame_num, faddr, fn ? fn : "(unknown)", ln);
                print_inline_chain(dwfl, (Dwarf_Addr)faddr);
            } else {
                Dwfl_Module* mod = dwfl_addrmodule(dwfl, (Dwarf_Addr)faddr);
                const char* sym = mod ? dwfl_module_addrname(mod, (Dwarf_Addr)faddr) : nullptr;
                printf("    frame %d: 0x%lx  ->  (no src - near symbol: %s)\n",
                       frame_num, faddr, sym ? sym : "unknown");
            }
            frame_num++;
        }
    } while (fgets(line, sizeof(line), fp));

    fclose(fp);
    dwfl_end(dwfl);
    return 0;
}
