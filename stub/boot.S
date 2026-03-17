// =============================================================================
// cm4_wipe_stub.S — Minimal AArch64 RAM sanitiser for Raspberry Pi CM4
// =============================================================================
//
// Purpose:
//   1. Preserve the ARM spin table (0x0–0xF7) and the device-tree blob.
//   2. Parse the DTB to discover all DRAM regions (via C helper).
//   3. Copy the embedded U-Boot image to its link address.
//   4. Enable MMU with identity map for fast cached zeroing (dc zva).
//   5. Zero every DRAM block not in a protected region.
//   6. Flush caches, disable MMU, hand off to U-Boot.
//
// Boot contract (set by VideoCore firmware):
//   x0  = DTB physical address
//   PC  = 0x200000  (default kernel_address for AArch64)
//   MMU = off, caches off, EL2 (default)
//   Secondary cores spinning on their spin-table release addresses.
//
// =============================================================================

.equ SPIN_TABLE_END,    0xF8
.equ UBOOT_DST,         0x01000000
.equ TRAMPOLINE_ADDR,   0xF8
.equ BLOCK_SIZE,        64              // dc zva block size on Cortex-A72
.equ MAX_MEM_REGIONS,   8

// Page table entry attribute bits (used as mov immediates, not orr)
//   Normal WB:  0x0701  = Block(01) | AF(1<<10) | SH_ISH(3<<8) | AttrIndx=0
//   Device:     0x0405  = Block(01) | AF(1<<10) | AttrIndx=1(1<<2)

// =============================================================================
.section .text
.global _start
.global uart_putc
.balign 16

_start:
    // ── Stage 0: Disable interrupts, set up stack ──────────────────────
    msr     DAIFSet, #0xF
    mov     x19, x0                     // x19 = DTB phys addr

    // Stack just below this stub (grows down from 0x200000)
    mov     sp, #0x200000

    mov     w0, #'S'
    bl      uart_putc

    // ── Stage 1: Validate DTB header ───────────────────────────────────
    ldr     w0, [x19]
    mov     w1, #0x0DD0
    movk    w1, #0xEDFE, lsl #16
    cmp     w0, w1
    b.ne    .Lhalt_dtb_magic

    ldr     w20, [x19, #4]
    rev     w20, w20
    cbz     w20, .Lhalt_dtb_size

    add     x20, x20, #0xFFF
    and     x20, x20, #~0xFFF

    mov     w0, #'1'
    bl      uart_putc

    // ── Stage 2: Parse DTB for memory regions (C code) ─────────────────
    mov     x0, x19
    adr     x1, _mem_regions
    mov     w2, #MAX_MEM_REGIONS
    bl      parse_dtb_memory

    cmp     w0, #0
    b.le    .Lhalt_parse_error

    mov     x28, x0

    mov     w0, #'2'
    bl      uart_putc

    // ── Stage 3: Overlap checks ────────────────────────────────────────
    adr     x1, _uboot_payload_start
    adr     x2, _uboot_payload_end
    sub     x21, x2, x1
    cbz     x21, .Lhalt_no_uboot

    mov     x3, UBOOT_DST
    add     x4, x3, x21                // U-Boot dest end

    // Check DTB vs U-Boot dest: [DTB, DTB+size) vs [UBOOT_DST, UBOOT_DST+size)
    add     x5, x19, x20               // DTB end
    cmp     x19, x4
    b.hs    .Lno_overlap_dtb_ub
    cmp     x3, x5
    b.hs    .Lno_overlap_dtb_ub
    b       .Lhalt_overlap
.Lno_overlap_dtb_ub:

    // Check U-Boot dest vs stub: [UBOOT_DST, UBOOT_DST+size) vs [_start, _stub_end)
    adr     x5, _start
    adr     x6, _stub_end
    cmp     x3, x6                     // UBOOT_DST >= stub_end?
    b.hs    .Lno_overlap_ub_stub
    cmp     x4, x5                     // UBOOT_DST_end <= _start?
    b.ls    .Lno_overlap_ub_stub
    b       .Lhalt_overlap
.Lno_overlap_ub_stub:

    mov     w0, #'3'
    bl      uart_putc

    // ── Stage 4: Copy embedded U-Boot to its link address ──────────────
    adr     x3, _uboot_payload_start
    mov     x4, UBOOT_DST
    add     x5, x3, x21

.Lcopy_uboot:
    cmp     x3, x5
    b.ge    .Lcopy_done
    ldp     x6, x7, [x3], #16
    stp     x6, x7, [x4], #16
    b       .Lcopy_uboot
.Lcopy_done:

    mov     w0, #'4'
    bl      uart_putc

    // ── Stage 4b: Enable MMU with identity map ─────────────────────────
    //
    // Build a level-1 page table with 1 GiB block descriptors:
    //   Entry 0: 0x00000000–0x3FFFFFFF → Normal Write-Back (DRAM)
    //   Entry 1: 0x40000000–0x7FFFFFFF → Normal Write-Back (DRAM)
    //   Entry 2: 0x80000000–0xBFFFFFFF → Normal Write-Back (DRAM)
    //   Entry 3: 0xC0000000–0xFFFFFFFF → Device-nGnRnE   (peripherals)
    //
    // This covers all DRAM for CM4 models up to 4 GiB. The GPU-reserved
    // region at the top of the first 1 GiB is excluded by the DTB memory
    // map, not by the page table — writes there are harmless but avoided.
    //
    // Cortex-A72 dc zva zeroes 64 bytes without a read-for-ownership,
    // giving ~10-20x speedup over non-cacheable stp stores.

    // Zero the page table (512 entries × 8 bytes = 4 KiB)
    adr     x0, _page_table
    mov     x1, #512
.Lzero_pt:
    str     xzr, [x0], #8
    subs    x1, x1, #1
    b.ne    .Lzero_pt

    // Fill entries using mov+movk (orr can't encode these constants)
    //
    // Normal WB attrs = 0x701 (Block | AF | Inner Shareable | AttrIndx=0)
    // Device attrs    = 0x405 (Block | AF | AttrIndx=1)
    adr     x0, _page_table

    // Entry 0: 0x00000000 → Normal WB
    mov     x1, #0x0701
    str     x1, [x0, #0]

    // Entry 1: 0x40000000 → Normal WB
    mov     x1, #0x0701
    movk    x1, #0x4000, lsl #16
    str     x1, [x0, #8]

    // Entry 2: 0x80000000 → Normal WB
    mov     x1, #0x0701
    movk    x1, #0x8000, lsl #16
    str     x1, [x0, #16]

    // Entry 3: 0xC0000000 → Device (peripherals at 0xFE000000)
    mov     x1, #0x0405
    movk    x1, #0xC000, lsl #16
    str     x1, [x0, #24]

    // Entries 4–7: high DRAM for 4/8 GiB CM4 models
    // 0x100000000–0x1FFFFFFFF (4 × 1 GiB blocks)

    // Entry 4: 0x100000000 → Normal WB
    mov     x1, #0x0701
    movk    x1, #0x0001, lsl #32
    str     x1, [x0, #32]

    // Entry 5: 0x140000000 → Normal WB
    mov     x1, #0x0701
    movk    x1, #0x4000, lsl #16
    movk    x1, #0x0001, lsl #32
    str     x1, [x0, #40]

    // Entry 6: 0x180000000 → Normal WB
    mov     x1, #0x0701
    movk    x1, #0x8000, lsl #16
    movk    x1, #0x0001, lsl #32
    str     x1, [x0, #48]

    // Entry 7: 0x1C0000000 → Normal WB
    mov     x1, #0x0701
    movk    x1, #0xC000, lsl #16
    movk    x1, #0x0001, lsl #32
    str     x1, [x0, #56]

    dsb     sy

    // MAIR_EL2: Attr0 = 0xFF (Normal WB RWA), Attr1 = 0x00 (Device-nGnRnE)
    mov     x1, #0xFF
    msr     mair_el2, x1

    // TTBR0_EL2: point to our page table
    adr     x1, _page_table
    msr     ttbr0_el2, x1

    // TCR_EL2:
    //   T0SZ  = 25  (39-bit VA → 512 GiB, level 1 = 512 × 1 GiB blocks)
    //   IRGN0 = 01  (Inner Write-Back Write-Allocate for table walks)
    //   ORGN0 = 01  (Outer Write-Back Write-Allocate for table walks)
    //   SH0   = 11  (Inner Shareable for table walks)
    //   TG0   = 00  (4 KiB granule)
    //   PS    = 010 (40-bit PA — supports up to 1 TiB, needed for >4 GiB)
    mov     x1, #0x19               // T0SZ = 25
    orr     x1, x1, #(1 << 8)      // IRGN0 = 01
    orr     x1, x1, #(1 << 10)     // ORGN0 = 01
    orr     x1, x1, #(3 << 12)     // SH0 = 11
    orr     x1, x1, #(2 << 16)     // PS = 010 (40-bit)
    msr     tcr_el2, x1

    isb

    // Enable MMU + data cache (SCTLR_EL2)
    mrs     x1, sctlr_el2
    orr     x1, x1, #(1 << 0)      // M  = MMU enable
    orr     x1, x1, #(1 << 2)      // C  = Data cache enable
    orr     x1, x1, #(1 << 12)     // I  = Instruction cache enable
    msr     sctlr_el2, x1
    isb

    // ── Stage 4c: Canary scan (PoC — runs with caches enabled) ────────
    //
    // void scan_canary(mem_region *regions, int count,
    //                  uint64_t stub_start, uint64_t stub_end)
    adr     x0, _mem_regions
    mov     w1, w28
    adr     x2, _start
    adr     x3, _stub_end
    bl      scan_canary

    // ── Stage 5: Wipe RAM (dc zva with write-back caching) ────────────
    //
    // dc zva allocates a clean zero cache line without reading from DRAM.
    // The cache controller writes back zero lines in efficient bursts.

    mov     x22, x19                    // DTB start
    add     x23, x19, x20              // DTB end
    mov     x24, UBOOT_DST             // UB start
    add     x25, x24, x21
    add     x25, x25, #63
    and     x25, x25, #~63            // UB end (aligned up to 64)
    adr     x26, _start                // Stub start
    adr     x27, _stub_end             // Stub end

    adr     x29, _mem_regions
    // x28 = region count

.Lregion_loop:
    cbz     x28, .Lwipe_done
    ldp     x0, x1, [x29], #16
    sub     x28, x28, #1

.Lwipe_loop:
    cmp     x0, x1
    b.ge    .Lregion_loop

    add     x2, x0, BLOCK_SIZE

    // Check A: spin table [0, 0xF8)
    cmp     x0, SPIN_TABLE_END
    b.lt    .Lskip

    // Check B: DTB
    cmp     x0, x23
    b.ge    .Lchk_uboot
    cmp     x2, x22
    b.le    .Lchk_uboot
    b       .Lskip

.Lchk_uboot:
    cmp     x0, x25
    b.ge    .Lchk_stub
    cmp     x2, x24
    b.le    .Lchk_stub
    b       .Lskip

.Lchk_stub:
    cmp     x0, x27
    b.ge    .Ldo_zero
    cmp     x2, x26
    b.le    .Ldo_zero
    b       .Lskip

.Ldo_zero:
    dc      zva, x0                     // Zero 64 bytes (one cache line)

.Lskip:
    add     x0, x0, BLOCK_SIZE
    b       .Lwipe_loop

.Lwipe_done:
    dsb     sy

    // ── Stage 5b: Flush caches and disable MMU ─────────────────────────
    //
    // Clean+invalidate all data cache lines by set/way, then disable MMU.
    // This ensures all zero lines are written back to DRAM.

    // Read CLIDR_EL1 to find number of cache levels (LoC)
    mrs     x0, clidr_el1
    ubfx    x3, x0, #24, #3            // x3 = LoC (Level of Coherence)
    cbz     x3, .Lflush_done
    mov     x10, xzr                   // x10 = current level (shifted ×2)

.Lflush_level:
    add     x2, x10, x10, lsr #1       // x2 = level × 3 (CLIDR bit position)
    lsr     x1, x0, x2
    and     x1, x1, #7                 // cache type at this level
    cmp     x1, #2                     // data or unified cache?
    b.lt    .Lflush_next_level

    msr     csselr_el1, x10            // select this cache level
    isb
    mrs     x1, ccsidr_el1

    and     x2, x1, #7                 // LineSize field
    add     x2, x2, #4                 // log2(line size in bytes)

    ubfx    x4, x1, #3, #10            // Associativity - 1 (max way)
    clz     w5, w4                     // bit position for way field

    ubfx    x6, x1, #13, #15           // NumSets - 1 (max set)

.Lflush_set:
    mov     x7, x4                     // way counter = max way
.Lflush_way:
    lsl     x8, x7, x5                // way field
    lsl     x9, x6, x2                // set field
    orr     x8, x8, x9
    orr     x8, x8, x10               // combine level, set, way
    dc      cisw, x8                   // Clean + Invalidate by Set/Way
    subs    x7, x7, #1
    b.ge    .Lflush_way
    subs    x6, x6, #1
    b.ge    .Lflush_set

.Lflush_next_level:
    add     x10, x10, #2               // next cache level
    cmp     x10, x3, lsl #1
    b.lt    .Lflush_level

.Lflush_done:
    dsb     sy
    isb

    // Disable MMU + caches
    mrs     x1, sctlr_el2
    bic     x1, x1, #(1 << 0)          // M = 0 (MMU off)
    bic     x1, x1, #(1 << 2)          // C = 0 (D-cache off)
    bic     x1, x1, #(1 << 12)         // I = 0 (I-cache off)
    msr     sctlr_el2, x1
    isb

    // Invalidate TLB
    tlbi    alle2
    dsb     sy
    isb

    mov     w0, #'5'
    bl      uart_putc

    // ── Stage 6: Trampoline — wipe the stub, then enter U-Boot ────────
    adr     x0, _trampoline_start
    adr     x1, _trampoline_end
    mov     x2, TRAMPOLINE_ADDR

.Lcopy_tramp:
    cmp     x0, x1
    b.ge    .Ltramp_ready
    ldr     w3, [x0], #4
    str     w3, [x2], #4
    b       .Lcopy_tramp

.Ltramp_ready:
    mov     w0, #'6'
    bl      uart_putc
    mov     w0, #'\n'
    bl      uart_putc

    adr     x0, _start
    adr     x1, _stub_end
    mov     x2, UBOOT_DST
    mov     x3, x19

    dsb     sy
    isb

    mov     x4, TRAMPOLINE_ADDR
    br      x4

// ── Trampoline (position-independent, relocated to 0xF8) ────────────
.balign 8
_trampoline_start:
    mov     x4, x2
.Ltr_wipe:
    cmp     x0, x1
    b.ge    .Ltr_jump
    stp     xzr, xzr, [x0], #16
    b       .Ltr_wipe
.Ltr_jump:
    mov     x0, x3
    br      x4
_trampoline_end:

// ── UART ────────────────────────────────────────────────────────────
uart_putc:
    mov     x16, #0x5054
    movk    x16, #0xFE21, lsl #16
.Luart_wait:
    ldr     w17, [x16]
    tbz     w17, #5, .Luart_wait
    mov     x16, #0x5040
    movk    x16, #0xFE21, lsl #16
    str     w0, [x16]
    ret

// ── Halt handlers ───────────────────────────────────────────────────
.Lhalt_dtb_magic:
    mov     w0, #'!'
    bl      uart_putc
    mov     w0, #'M'
    bl      uart_putc
    b       .Lnuclear_wipe

.Lhalt_dtb_size:
    mov     w0, #'!'
    bl      uart_putc
    mov     w0, #'Z'
    bl      uart_putc
    b       .Lnuclear_wipe

.Lhalt_parse_error:
    mov     w0, #'!'
    bl      uart_putc
    mov     w0, #'E'
    bl      uart_putc
    b       .Lnuclear_wipe

.Lhalt_no_uboot:
    mov     w0, #'!'
    bl      uart_putc
    mov     w0, #'U'
    bl      uart_putc
    b       .Lnuclear_wipe

.Lhalt_overlap:
    mov     w0, #'!'
    bl      uart_putc
    mov     w0, #'O'
    bl      uart_putc
    b       .Lnuclear_wipe

// ── Nuclear wipe — emergency DRAM sanitisation on error ─────────────
//
// No DTB, no memory map, no mercy. Assumes worst-case 8 GiB CM4.
// Zeros everything the ARM can reach, preserving only:
//   - [0x00, 0xF8)     spin table (secondary cores need this)
//   - [_start, _stub_end) this running code (wiped by trampoline after)
//
// Uses the MMU + dc zva fast path for maximum speed.
// After the wipe, the system halts — there is no U-Boot to boot into
// (we got here because something is wrong), but the DRAM is clean.

.Lnuclear_wipe:
    mov     w0, #'W'
    bl      uart_putc

    // ── Set up MMU (same identity map as normal path) ──────────────
    adr     x0, _page_table
    mov     x1, #512
.Lnuke_zero_pt:
    str     xzr, [x0], #8
    subs    x1, x1, #1
    b.ne    .Lnuke_zero_pt

    adr     x0, _page_table

    mov     x1, #0x0701
    str     x1, [x0, #0]               // 0x00000000 Normal WB

    mov     x1, #0x0701
    movk    x1, #0x4000, lsl #16
    str     x1, [x0, #8]               // 0x40000000 Normal WB

    mov     x1, #0x0701
    movk    x1, #0x8000, lsl #16
    str     x1, [x0, #16]              // 0x80000000 Normal WB

    mov     x1, #0x0405
    movk    x1, #0xC000, lsl #16
    str     x1, [x0, #24]              // 0xC0000000 Device

    mov     x1, #0x0701
    movk    x1, #0x0001, lsl #32
    str     x1, [x0, #32]              // 0x100000000 Normal WB

    mov     x1, #0x0701
    movk    x1, #0x4000, lsl #16
    movk    x1, #0x0001, lsl #32
    str     x1, [x0, #40]              // 0x140000000 Normal WB

    mov     x1, #0x0701
    movk    x1, #0x8000, lsl #16
    movk    x1, #0x0001, lsl #32
    str     x1, [x0, #48]              // 0x180000000 Normal WB

    mov     x1, #0x0701
    movk    x1, #0xC000, lsl #16
    movk    x1, #0x0001, lsl #32
    str     x1, [x0, #56]              // 0x1C0000000 Normal WB

    dsb     sy

    mov     x1, #0xFF
    msr     mair_el2, x1

    adr     x1, _page_table
    msr     ttbr0_el2, x1

    mov     x1, #0x19
    orr     x1, x1, #(1 << 8)
    orr     x1, x1, #(1 << 10)
    orr     x1, x1, #(3 << 12)
    orr     x1, x1, #(2 << 16)
    msr     tcr_el2, x1

    isb

    mrs     x1, sctlr_el2
    orr     x1, x1, #(1 << 0)
    orr     x1, x1, #(1 << 2)
    orr     x1, x1, #(1 << 12)
    msr     sctlr_el2, x1
    isb

    // ── Wipe all DRAM regions, 8 GiB worst case ───────────────────
    //
    // Region layout (BCM2711):
    //   Low:  0x00000000–0xBFFFFFFF (3 GiB max ARM-accessible)
    //   Gap:  0xC0000000–0xFFFFFFFF (peripherals — skip)
    //   High: 0x100000000–0x1FFFFFFFF (4 GiB on 8 GiB models)
    //
    // Protected: spin table [0, 0xF8) and stub [_start, _stub_end)
    // Everything else gets obliterated.

    adr     x10, _start
    adr     x11, _stub_end

    // ── Low DRAM: 0x00 → 0xC0000000 ──────────────────────────────
    mov     x0, SPIN_TABLE_END          // Start after spin table
    mov     x1, #0xC000
    movk    x1, #0x0000, lsl #0
    lsl     x1, x1, #16                // x1 = 0xC0000000

.Lnuke_low:
    cmp     x0, x1
    b.ge    .Lnuke_high

    // Skip stub region
    cmp     x0, x11                     // cursor >= stub_end?
    b.ge    .Lnuke_low_do
    add     x2, x0, BLOCK_SIZE
    cmp     x2, x10                    // block_end <= stub_start?
    b.le    .Lnuke_low_do
    // Overlaps stub — skip
    add     x0, x0, BLOCK_SIZE
    b       .Lnuke_low

.Lnuke_low_do:
    dc      zva, x0
    add     x0, x0, BLOCK_SIZE
    b       .Lnuke_low

    // ── High DRAM: 0x100000000 → 0x200000000 ─────────────────────
.Lnuke_high:
    movz    x0, #0x0001, lsl #32       // 0x100000000
    movz    x1, #0x0002, lsl #32       // 0x200000000

.Lnuke_high_loop:
    cmp     x0, x1
    b.ge    .Lnuke_flush
    dc      zva, x0
    add     x0, x0, BLOCK_SIZE
    b       .Lnuke_high_loop

    // ── Flush caches + disable MMU ────────────────────────────────
.Lnuke_flush:
    dsb     sy

    mrs     x0, clidr_el1
    ubfx    x3, x0, #24, #3
    cbz     x3, .Lnuke_flush_done
    mov     x12, xzr

.Lnuke_flush_level:
    add     x2, x12, x12, lsr #1
    lsr     x1, x0, x2
    and     x1, x1, #7
    cmp     x1, #2
    b.lt    .Lnuke_flush_next

    msr     csselr_el1, x12
    isb
    mrs     x1, ccsidr_el1

    and     x2, x1, #7
    add     x2, x2, #4
    ubfx    x4, x1, #3, #10
    clz     w5, w4
    ubfx    x6, x1, #13, #15

.Lnuke_flush_set:
    mov     x7, x4
.Lnuke_flush_way:
    lsl     x8, x7, x5
    lsl     x9, x6, x2
    orr     x8, x8, x9
    orr     x8, x8, x12
    dc      cisw, x8
    subs    x7, x7, #1
    b.ge    .Lnuke_flush_way
    subs    x6, x6, #1
    b.ge    .Lnuke_flush_set

.Lnuke_flush_next:
    add     x12, x12, #2
    cmp     x12, x3, lsl #1
    b.lt    .Lnuke_flush_level

.Lnuke_flush_done:
    dsb     sy
    isb

    mrs     x1, sctlr_el2
    bic     x1, x1, #(1 << 0)
    bic     x1, x1, #(1 << 2)
    bic     x1, x1, #(1 << 12)
    msr     sctlr_el2, x1
    isb

    tlbi    alle2
    dsb     sy
    isb

    // ── Hardware reset via BCM2711 watchdog ─────────────────────────
    //
    // PM_WDOG  = 0xFE100024  (watchdog timer)
    // PM_RSTC  = 0xFE10001C  (reset control)
    // Password = 0x5A000000  (required in top 8 bits of every write)
    //
    // Set watchdog to minimum timeout, trigger full reset.
    // The VideoCore handles the actual reset sequence.

    mov     w0, #'X'                    // "X" = resetting
    bl      uart_putc
    mov     w0, #'\n'
    bl      uart_putc

    mov     x0, #0x0024
    movk    x0, #0xFE10, lsl #16       // PM_WDOG = 0xFE100024
    mov     w1, #0x000A                 // 10 ticks (~150µs)
    movk    w1, #0x5A00, lsl #16       // password
    str     w1, [x0]

    mov     x0, #0x001C
    movk    x0, #0xFE10, lsl #16       // PM_RSTC = 0xFE10001C
    mov     w1, #0x0020                 // WRCFG_FULL_RESET
    movk    w1, #0x5A00, lsl #16       // password
    str     w1, [x0]

    // Spin until the watchdog fires
    dsb     sy
.Lnuke_wait_reset:
    wfe
    b       .Lnuke_wait_reset

// ── Data ────────────────────────────────────────────────────────────

// Level-1 page table (512 × 8 = 4 KiB, must be 4 KiB-aligned)
.balign 4096
_page_table:
    .space  4096

// Memory region table (filled by C parser)
.balign 16
_mem_regions:
    .space  MAX_MEM_REGIONS * 16

// Embedded U-Boot payload
.balign 16
_uboot_payload_start:
    .incbin "u-boot.bin"
_uboot_payload_end:
.balign 64                              // Align to wipe block size so protection
                                        // boundary matches dc zva granularity
_stub_end:
