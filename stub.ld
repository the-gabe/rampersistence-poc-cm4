ENTRY(_start)
SECTIONS
{
    . = 0x200000;
    .text : {
        KEEP(boot.o(.text))
        *(.text .text.*)
        *(.rodata)
        *(.rodata.*)
    }
    .data : {
        *(.data)
        *(.data.*)
    }
    .bss : {
        *(.bss)
        *(.bss.*)
    }
}
