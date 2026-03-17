/*
 * write-canary.c — Stamp canary string into free DRAM pages.
 *
 * Allocates as much anonymous memory as possible, fills it with
 * a repeating canary string, then locks it into RAM with mlock().
 * The kernel only gives us genuinely free pages — no corruption.
 *
 * After stamping, the process stays alive (holding the pages).
 * Run panic-reboot from another terminal/script to trigger a
 * dirty reset. The canary pages persist in DRAM.
 *
 * Usage: sudo ./write-canary
 *        (then from another terminal: sudo panic-reboot)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>

#define CANARY "THISISNOTMEANTTOBEREADABLE!"
#define CANARY_LEN 28
#define PAGE_SIZE 4096
#define CHUNK (64 * 1024 * 1024UL)  /* Allocate in 64 MiB chunks */

static void fill_canary(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = CANARY[i % CANARY_LEN];
}

int main(void)
{
    if (getuid() != 0) {
        fprintf(stderr, "Must run as root (for mlock)\n");
        return 1;
    }

    /* Figure out how much free memory we can grab.
     * Leave 64 MiB for the kernel/system to breathe. */
    struct sysinfo si;
    sysinfo(&si);
    uint64_t free_bytes = (uint64_t)si.freeram * si.mem_unit;
    uint64_t target = free_bytes > (64 << 20) ? free_bytes - (64 << 20) : 0;

    if (target < CHUNK) {
        fprintf(stderr, "Not enough free RAM (%lu MiB free)\n", free_bytes >> 20);
        return 1;
    }

    printf("Free RAM: %lu MiB, will stamp %lu MiB with canary\n",
           free_bytes >> 20, target >> 20);
    printf("Canary: \"%s\"\n\n", CANARY);

    /* Allocate in chunks, fill with canary, mlock to prevent swapout */
    uint64_t total_locked = 0;
    int nchunks = 0;

    /* Keep track of allocations so we hold them */
    void **chunks = NULL;
    int max_chunks = (target / CHUNK) + 1;
    chunks = malloc(max_chunks * sizeof(void *));
    if (!chunks) { perror("malloc"); return 1; }

    while (total_locked + CHUNK <= target) {
        void *p = mmap(NULL, CHUNK, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                       -1, 0);
        if (p == MAP_FAILED)
            break;

        /* Fill with canary */
        fill_canary(p, CHUNK);

        /* Lock into physical RAM — prevents the kernel from reclaiming */
        if (mlock(p, CHUNK) != 0) {
            /* Can't lock — probably hit the limit. Still useful,
             * the pages are populated and likely to stay. */
            munmap(p, CHUNK);
            break;
        }

        chunks[nchunks++] = p;
        total_locked += CHUNK;

        printf("  Locked %lu MiB...\n", total_locked >> 20);
    }

    printf("\nDone: %lu MiB stamped and locked (%d chunks)\n",
           total_locked >> 20, nchunks);
    printf("\nPages are locked in physical RAM.\n");

    /* Trigger watchdog reset directly — no need for a second process.
     * Same as panic-reboot: write PM registers via /dev/mem. */
    printf("Triggering watchdog reset in 2 seconds...\n");
    fflush(stdout);
    sleep(2);

    int fd = open("/dev/mem", 2 /* O_RDWR */ | 0x101000 /* O_SYNC */);
    if (fd < 0) {
        perror("/dev/mem");
        printf("Failed to open /dev/mem — run panic-reboot manually\n");
        getchar();
        return 1;
    }

    void *pm = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED,
                    fd, 0xfe100000);
    if (pm == MAP_FAILED) {
        perror("mmap PM registers");
        close(fd);
        printf("Failed to map PM registers — run panic-reboot manually\n");
        getchar();
        return 1;
    }

    printf("Resetting NOW.\n");
    fflush(stdout);

    volatile uint32_t *pm_wdog = (volatile uint32_t *)((uint8_t *)pm + 0x24);
    volatile uint32_t *pm_rstc = (volatile uint32_t *)((uint8_t *)pm + 0x1c);

    *pm_wdog = 0x5a00000a;  /* password | 10 ticks */
    *pm_rstc = 0x5a000020;  /* password | full reset */

    /* Should never reach here */
    while (1) __asm__ volatile("wfe");
    return 0;
}
