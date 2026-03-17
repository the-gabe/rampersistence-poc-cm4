// fdt_parse.c — Minimal freestanding FDT parser + canary scanner
//
// Called from bare-metal AArch64 stub. No libc, no libfdt.
// Compiled with -ffreestanding -nostdlib -mgeneral-regs-only.

typedef unsigned char      uint8_t;
typedef unsigned int        uint32_t;
typedef unsigned long       uint64_t;
typedef unsigned long       uintptr_t;

#define FDT_BEGIN_NODE  1
#define FDT_END_NODE    2
#define FDT_PROP        3
#define FDT_NOP         4
#define FDT_END         9

struct mem_region {
    uint64_t base;
    uint64_t end;
};

// Provided by boot.S
extern void uart_putc(int ch);

static void uart_puts(const char *s)
{
    while (*s) uart_putc(*s++);
}

static void uart_puthex(uint64_t val)
{
    static const char hex[] = "0123456789abcdef";
    uart_puts("0x");
    int started = 0;
    for (int i = 60; i >= 0; i -= 4) {
        int nibble = (val >> i) & 0xF;
        if (nibble || started || i == 0) {
            uart_putc(hex[nibble]);
            started = 1;
        }
    }
}

static uint32_t be32(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8)  |  (uint32_t)b[3];
}

static uint64_t read_cells(const uint8_t **p, int cells)
{
    uint64_t val = 0;
    for (int i = 0; i < cells; i++) {
        val = (val << 32) | be32(*p);
        *p += 4;
    }
    return val;
}

static int streq(const char *a, const char *b)
{
    while (*a && *b) {
        if (*a++ != *b++) return 0;
    }
    return *a == *b;
}

static int has_prefix(const char *s, const char *pfx)
{
    while (*pfx) {
        if (*s++ != *pfx++) return 0;
    }
    return 1;
}

static const uint8_t *align4(const uint8_t *p)
{
    return (const uint8_t *)(((uintptr_t)p + 3) & ~(uintptr_t)3);
}

// Parse DTB for /memory node reg properties.
//
// Returns: number of regions found (>0), or negative error code:
//   -1  #address-cells > 2
//   -2  #size-cells > 2
//   -3  too many memory regions
//   -4  no memory regions found
//   -5  malformed FDT token
int parse_dtb_memory(const void *dtb, struct mem_region *regions, int max_regions)
{
    const uint8_t *base = (const uint8_t *)dtb;

    uint32_t off_struct  = be32(base + 0x08);
    uint32_t off_strings = be32(base + 0x0C);

    const uint8_t *cursor  = base + off_struct;
    const char    *strings = (const char *)(base + off_strings);

    int depth      = 0;
    int in_memory  = 0;
    int addr_cells = 2;   // ePAPR default
    int size_cells = 1;   // ePAPR default
    int count      = 0;

    uart_putc('P');

    for (;;) {
        uint32_t token = be32(cursor);
        cursor += 4;

        switch (token) {

        case FDT_BEGIN_NODE: {
            depth++;
            const char *name = (const char *)cursor;

            if (depth == 2 &&
                has_prefix(name, "memory") &&
                (name[6] == '\0' || name[6] == '@'))
            {
                in_memory = 1;
                uart_putc('m');
            }

            // Advance past null-terminated name, pad to 4
            while (*cursor) cursor++;
            cursor++;                       // skip '\0'
            cursor = align4(cursor);
            break;
        }

        case FDT_END_NODE:
            if (depth == 2) in_memory = 0;
            depth--;
            break;

        case FDT_PROP: {
            uint32_t len     = be32(cursor); cursor += 4;
            uint32_t nameoff = be32(cursor); cursor += 4;
            const uint8_t *data      = cursor;
            const char    *prop_name = strings + nameoff;

            // Root properties (depth 1)
            if (depth == 1) {
                if (streq(prop_name, "#address-cells")) {
                    addr_cells = (int)be32(data);
                    if (addr_cells > 2) return -1;
                } else if (streq(prop_name, "#size-cells")) {
                    size_cells = (int)be32(data);
                    if (size_cells > 2) return -2;
                }
            }

            // Memory reg property (depth 2, inside memory node)
            if (depth == 2 && in_memory && streq(prop_name, "reg")) {
                const uint8_t *p   = data;
                const uint8_t *end = data + len;

                while (p < end) {
                    uint64_t rbase = read_cells(&p, addr_cells);
                    uint64_t rsize = read_cells(&p, size_cells);

                    if (rsize == 0) continue;
                    if (count >= max_regions) return -3;

                    regions[count].base = rbase;
                    regions[count].end  = rbase + rsize;
                    count++;
                    uart_putc('r');
                }
            }

            // Skip past property data (align to 4)
            cursor = align4(data + len);
            break;
        }

        case FDT_NOP:
            break;

        case FDT_END:
            return count > 0 ? count : -4;

        default:
            uart_putc('?');
            return -5;
        }
    }
}

// =============================================================================
// Canary scanner — proves DRAM contents survive warm reboot
// =============================================================================

#define CANARY_STR "THISISNOTMEANTTOBEREADABLE!"
#define CANARY_LEN 28

static int memcmp8(const volatile uint8_t *a, const uint8_t *b, int n)
{
    for (int i = 0; i < n; i++)
        if (a[i] != b[i]) return 1;
    return 0;
}

void scan_canary(const struct mem_region *regions, int count,
                 uint64_t stub_start, uint64_t stub_end)
{
    const uint8_t *canary = (const uint8_t *)CANARY_STR;
    uint64_t found = 0;
    uint64_t pages_checked = 0;
    uint64_t first_addr = 0;
    uint64_t last_addr = 0;

    uart_puts("\r\n=== CANARY SCAN ===\r\n");
    uart_puts("Looking for: \"" CANARY_STR "\"\r\n");

    for (int r = 0; r < count; r++) {
        uint64_t base = regions[r].base;
        uint64_t end  = regions[r].end;

        uart_puts("Scanning ");
        uart_puthex(base);
        uart_puts("-");
        uart_puthex(end);
        uart_puts("\r\n");

        uint64_t next_dot = base + (64 << 20);

        // Check every page (4 KiB stride) — canary is page-aligned
        for (uint64_t addr = base; addr + CANARY_LEN <= end; addr += 4096) {
            if (addr >= next_dot) {
                uart_putc('.');
                next_dot += (64 << 20);
            }

            // Skip stub
            if (addr >= stub_start && addr < stub_end)
                continue;

            volatile const uint8_t *p = (volatile const uint8_t *)addr;

            // Quick check: first 4 bytes = "THIS"
            if (p[0] != 'T' || p[1] != 'H' || p[2] != 'I' || p[3] != 'S')
                continue;

            // Full compare
            if (memcmp8(p, canary, CANARY_LEN) == 0) {
                found++;
                if (found == 1) first_addr = addr;
                last_addr = addr;

                // Print first few and then every 10000th
                if (found <= 5 || found % 10000 == 0) {
                    uart_puts("  CANARY @ ");
                    uart_puthex(addr);
                    uart_puts("\r\n");
                }
            }
            pages_checked++;
        }
    }

    uart_puts("\r\n\r\nResults: ");
    uart_puthex(found);
    uart_puts(" pages still contain canary out of ");
    uart_puthex(pages_checked);
    uart_puts(" checked\r\n");

    if (found) {
        uart_puts("Range: ");
        uart_puthex(first_addr);
        uart_puts(" - ");
        uart_puthex(last_addr);
        uart_puts("\r\n");
        uart_puts("CONCLUSION: DRAM contents SURVIVED warm reboot\r\n");
    } else {
        uart_puts("CONCLUSION: No canary found — DRAM was cleared\r\n");
    }
    uart_puts("===================\r\n");
}

