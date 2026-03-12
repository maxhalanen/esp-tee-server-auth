/*
 * SPDX-FileCopyrightText: 2024-2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * Automatically generated file. DO NOT EDIT.
 * Espressif IoT Development Framework (ESP-IDF) 6.1.0 Configuration Header
 */
       
/* List of deprecated options */
/* CPU instruction prefetch padding size for flash mmap scenario */
/*
 * PMP region granularity size
 * Software may determine the PMP granularity by writing zero to pmp0cfg, then writing all ones
 * to pmpaddr0, then reading back pmpaddr0. If G is the index of the least-significant bit set,
 * the PMP granularity is 2^G+2 bytes.
 */
/* TEE interrupt stack is placed at the end of the TEE DRAM segment.
 * The top of the TEE stack is before the end of interrupt stack
 * and the bottom of the stack is at _heap_end.
 */
/**
 * These values are the same in every app binary for the same chip target.
 *
 * Values that may change when the app is rebuilt, or in a new ESP-IDF version,
 * should be stored via esp_app_tee_config structure
 */
PROVIDE ( esp_tee_app_config = ((0x40800000) + 0x8000 + 0x5000) + 0x2e0 );
PROVIDE ( GDMA = 0x60080000 );
/* SPI Flash functions required from the ROM (refer esp32c6.rom.spiflash.ld) */
PROVIDE ( spi_flash_check_and_flush_cache = 0x4000021c );
PROVIDE ( spi_flash_chip_generic_config_host_io_mode = 0x400002c4 );
PROVIDE ( memspi_host_flush_cache = 0x40000308 );
/* Default entry point: */
ENTRY(esp_tee_init);
MEMORY
{
/* Flash text section */
  irom_tee_seg (RX): org = (0x42000000) + 0x20, len = (0x20000 + 0x10000) - 0x20
/* Flash data section */
  drom_tee_seg (R) : org = (0x42000000) + 0x20, len = (0x20000 + 0x10000) - 0x20
/* I/DRAM section */
  sram_tee_seg (RWX) : org = (0x40800000), len = (0x8000 + (0x5000 - 0xc00 - 0x400))
/* Stack section */
  stack_tee_seg (RW) : org = (((0x40800000) + 0x8000 + (0x5000 - 0xc00 - 0x400))), len = 0xc00
/* Interrupt stack section */
  intr_stack_tee_seg (RW) : org = (((0x40800000) + 0x8000 + (0x5000 - 0xc00 - 0x400)) + 0xc00), len = 0x400
}
SECTIONS
{
  .iram.tee.text :
  {
    /* Vectors go to start of IRAM */
    ASSERT(ABSOLUTE(.) % 0x100 == 0, "vector address must be 256 byte aligned");
    _tee_vec_start = ABSOLUTE(.);
    KEEP(*(.exception_vectors_table.text));
    KEEP(*(.exception_vectors.text));
    . = ALIGN(4); _invalid_pc_placeholder = ABSOLUTE(.);
    _tee_vec_end = ABSOLUTE(.);
    /* Code marked as running out of IRAM */
    _tee_iram_start = ABSOLUTE(.);
    *(.iram1 .iram1.*)
    /* TEE initialization */
    *libmain.a:esp_tee_init.c*(.literal .text .literal.* .text.*)
    *libmain.a:esp_tee_secure_sys_cfg.c*(.literal .text .literal.* .text.*)
    *libmain.a:esp_tee_pmp_pma_prot_cfg.c*(.literal .text .literal.* .text.*)
    *libmain.a:esp_tee_apm_prot_cfg.c*(.literal .text .literal.* .text.*)
    *libmain.a:brownout.c*(.literal .text .literal.* .text.*)
    *libmain.a:multi_heap.c*(.literal .text .literal.* .text.*)
    /* Panic handler */
    *libmain.a:esp_tee_panic.c*(.literal .text .literal.* .text.*)
    *libmain.a:panic_helper_riscv.c*(.literal .text .literal.* .text.*)
    /* Service call execution */
    *libmain.a:esp_tee_vectors_plic.S*(.literal .text .literal.* .text.*)
    *libmain.a:esp_secure_dispatcher.c*(.literal .text .literal.* .text.*)
    *libmain.a:esp_secure_services_iram.c*(.literal .text .literal.* .text.*)
    /* Interrupt configuration */
    *libmain.a:esp_tee_intr.c*(.literal .text .literal.* .text.*)
    *libmain.a:esp_tee_apm_intr.c*(.literal .text .literal.* .text.*)
    /* HAL */
    *libhal.a:mmu_hal.c*(.literal .text .literal.* .text.*)
    *libhal.a:cache_hal.c*(.literal .text .literal.* .text.*)
    *libhal.a:apm_hal.c*(.literal .text .literal.* .text.*)
    *libesp_hal_mspi.a:*(.literal .text .literal.* .text.*)
    *libesp_hal_wdt.a:*(.literal .text .literal.* .text.*)
    /* IDF components */
    *libbootloader_support.a:*(.literal .text .literal.* .text.*)
    *libesp_hw_support.a:*(.literal .text .literal.* .text.*)
    *liblog.a:*(.literal .text .literal.* .text.*)
    *libriscv.a:*(.literal .text .literal.* .text.*)
    /* TEE services: Secure storage, OTA, attestation */
    *libtee_flash_mgr.a:*(.literal .text .literal.* .text.*)
    *libtee_sec_storage.a:*(.literal .text .literal.* .text.*)
    *libtee_ota_ops.a:*(.literal .text .literal.* .text.*)
    *libtee_attestation.a:*(.literal .text .literal.* .text.*)
    /* Align the end of code region as per PMP region granularity */
    . = ALIGN(4); _tee_iram_end = ABSOLUTE(.);
  } > sram_tee_seg
  .dram.tee.data :
  {
    _tee_dram_start = ABSOLUTE(.);
    _tee_data_start = ABSOLUTE(.);
    *(.data .data.*)
    *(.sdata .sdata.*)
    *(.dram1 .dram1.*)
    _tee_data_end = ABSOLUTE(.);
   } > sram_tee_seg
  .dram.tee.bss (NOLOAD) :
  {
    . = ALIGN(8); _tee_bss_start = ABSOLUTE(.);
    *(.bss .bss.*)
    *(.sbss .sbss.*)
    . = ALIGN(8); _tee_bss_end = ABSOLUTE(.);
  } > sram_tee_seg
  .dram.tee.tdata :
  {
    /* tdata sections */
    _tee_tdata_start = ABSOLUTE(.);
    KEEP(*(.tdata.errno))
    *(.tdata .tdata.* .gnu.linkonce.td.*)
    _tee_tdata_end = ABSOLUTE(.);
    /* tbss sections */
    _tee_tbss_start = ABSOLUTE(.);
    *(.tbss .tbss.* .gnu.linkonce.tb.*)
    *(.tcommon .tcommon.*)
    _tee_tbss_end = ABSOLUTE(.);
    . = ALIGN(ALIGNOF(.dram.tee.rodata));
  } > sram_tee_seg
  ASSERT((ADDR(.dram.tee.rodata) == ADDR(.dram.tee.tdata) + SIZEOF(.dram.tee.tdata)), "The gap between .dram.tee.tdata and .dram.tee.rodata must not exist to produce the final bin image.")
  ASSERT(_tee_tdata_end == _tee_tbss_start,
         "tdata and tbss must be contiguous.")
  .dram.tee.rodata :
  {
    _tee_rodata_start = ABSOLUTE(.);
    /* TEE flash manager */
    *libtee_flash_mgr.a:*(.rodata .srodata .rodata.* .srodata.*)
    *libbootloader_support.a:bootloader_flash.*(.rodata .srodata .rodata.* .srodata.*)
    /* Secure services */
    *libmain.a:esp_secure_services_iram.c.*(.rodata .srodata .rodata.* .srodata.*)
    *libmain.a:esp_secure_dispatcher.c.*(.rodata .srodata .rodata.* .srodata.*)
    /* Panic handler */
    *libmain.a:panic_helper_riscv.*(.rodata .srodata .rodata.* .srodata.*)
    *libmain.a:esp_tee_apm_intr.c.*(.rodata .srodata .rodata.* .srodata.*)
    /* HAL (noflash) */
    *libhal.a:mmu_hal.c*(.rodata .srodata .rodata.* .srodata.*)
    *libhal.a:cache_hal.c*(.rodata .srodata .rodata.* .srodata.*)
    *libesp_hal_mspi.a:*(.rodata .srodata .rodata.* .srodata.*)
    _tee_rodata_end = ABSOLUTE(.);
    _tee_dram_end = ABSOLUTE(.);
  } > sram_tee_seg
  .dram.tee.heap (NOLOAD): ALIGN(0x10)
  {
    _tee_heap_start = ABSOLUTE(.);
    . = ORIGIN(sram_tee_seg) + LENGTH(sram_tee_seg);
    _tee_heap_end = ABSOLUTE(.);
  } > sram_tee_seg
  .dram.tee.stack (NOLOAD): ALIGN(0x10)
  {
    _tee_stack_bottom = ABSOLUTE(.);
    . = ORIGIN(stack_tee_seg) + LENGTH(stack_tee_seg);
    _tee_stack = ABSOLUTE(.);
  } > stack_tee_seg
  .dram.tee.intr_stack (NOLOAD): ALIGN(0x10)
  {
    _tee_intr_stack_bottom = ABSOLUTE(.);
    . = ORIGIN(intr_stack_tee_seg) + LENGTH(intr_stack_tee_seg);
    _tee_intr_stack = ABSOLUTE(.);
  } > intr_stack_tee_seg
  .flash.tee.rodata : ALIGN(0x10)
  {
    _tee_flash_data_start = ABSOLUTE(.);
    *(.rodata_desc .rodata_desc.*) /* Should be the first. TEE App version info. DO NOT PUT ANYTHING BEFORE IT! */
    *(.rodata .rodata.*)
    *(.srodata .srodata.*)
    *(.gcc_except_table .gcc_except_table.*)
    _tee_flash_data_end = ABSOLUTE(.);
   } > drom_tee_seg
  .flash.tee.text_dummy (NOLOAD):
  {
    /* Create an empty gap as big as .flash.tee.rodata section */
    . = ALIGN(ALIGNOF(.flash.tee.rodata)) + SIZEOF(.flash.tee.rodata);
    /* Add alignment of MMU page size + 0x20 bytes for the mapping header. */
    . = ALIGN(0x8000) + 0x20;
  } > irom_tee_seg
  .flash.tee.text :
  {
    _tee_flash_text_start = ABSOLUTE(.);
    *(.literal .text .literal.* .text.*)
    *(.stub .gnu.warning .gnu.linkonce.literal.* .gnu.linkonce.t.*.literal .gnu.linkonce.t.*)
    /**
     * CPU will try to prefetch up to 16 bytes of of instructions.
     * This means that any configuration (e.g. MMU, PMS) must allow
     * safe access to up to 16 bytes after the last real instruction, add
     * dummy bytes to ensure this
     */
    . += 16;
    _tee_flash_text_end = ABSOLUTE(.);
   } > irom_tee_seg
  /**
   * This section is not included in the binary image; it is only present in the ELF file.
   * It is used to keep certain symbols in the ELF file.
   */
  .noload 0 (INFO) :
  {
    /* Reserve first 4 bytes as zero for vars pointed to NULL */
    . = 0;
    LONG(0);
    _noload_keep_in_elf_start = ABSOLUTE(.);
    KEEP(*(.noload_keep_in_elf .noload_keep_in_elf.*))
    mapping[noload_keep_in_elf]
    _noload_keep_in_elf_end = ABSOLUTE(.);
  }
  /* DWARF 1 */
  .debug 0 : { *(.debug) }
  .line 0 : { *(.line) }
  /* GNU DWARF 1 extensions */
  .debug_srcinfo 0 : { *(.debug_srcinfo) }
  .debug_sfnames 0 : { *(.debug_sfnames) }
  /* DWARF 1.1 and DWARF 2 */
  .debug_aranges 0 : { *(.debug_aranges) }
  .debug_pubnames 0 : { *(.debug_pubnames) }
  /* DWARF 2 */
  .debug_info 0 : { *(.debug_info .gnu.linkonce.wi.*) }
  .debug_abbrev 0 : { *(.debug_abbrev) }
  .debug_line 0 : { *(.debug_line) }
  .debug_frame 0 : { *(.debug_frame) }
  .debug_str 0 : { *(.debug_str) }
  .debug_loc 0 : { *(.debug_loc) }
  .debug_macinfo 0 : { *(.debug_macinfo) }
  .debug_pubtypes 0 : { *(.debug_pubtypes) }
  /* DWARF 3 */
  .debug_ranges 0 : { *(.debug_ranges) }
  /* SGI/MIPS DWARF 2 extensions */
  .debug_weaknames 0 : { *(.debug_weaknames) }
  .debug_funcnames 0 : { *(.debug_funcnames) }
  .debug_typenames 0 : { *(.debug_typenames) }
  .debug_varnames 0 : { *(.debug_varnames) }
  /* GNU DWARF 2 extensions */
  .debug_gnu_pubnames 0 : { *(.debug_gnu_pubnames) }
  .debug_gnu_pubtypes 0 : { *(.debug_gnu_pubtypes) }
  /* DWARF 4 */
  .debug_types 0 : { *(.debug_types) }
  /* DWARF 5 */
  .debug_addr 0 : { *(.debug_addr) }
  .debug_line_str 0 : { *(.debug_line_str) }
  .debug_loclists 0 : { *(.debug_loclists) }
  .debug_macro 0 : { *(.debug_macro) }
  .debug_names 0 : { *(.debug_names) }
  .debug_rnglists 0 : { *(.debug_rnglists) }
  .debug_str_offsets 0 : { *(.debug_str_offsets) }
  .comment 0 : { *(.comment) }
  .note.GNU-stack 0: { *(.note.GNU-stack) }
  .riscv.attributes 0: { *(.riscv.attributes) }
  /DISCARD/ :
  {
   /**
    * Discarding .rela.* sections results in the following mapping:
    * .rela.text.* -> .text.*
    * .rela.data.* -> .data.*
    * And so forth...
    */
   *(.rela.*)
   *(.got .got.plt) /* TODO: GCC-382 */
  }
}
ASSERT ((_tee_iram_end <= _tee_dram_start),
        "Error: TEE IRAM segment overflowed into the DRAM segment! Increase CONFIG_SECURE_TEE_IRAM_SIZE as required.");
ASSERT((_tee_heap_end >= _tee_heap_start + 0x2000),
        "Error: TEE heap size is too small - minimum is 8KB (0x2000)! Increase CONFIG_SECURE_TEE_DRAM_SIZE as required.");
/* MMU Page Alignment Checks */
ASSERT ((0x20000 % 0x8000) == 0,
        "Error: SECURE_TEE_IROM_SIZE must be a multiple of MMU_PAGE_SIZE (CONFIG_MMU_PAGE_SIZE)!");
ASSERT ((0x10000 % 0x8000) == 0,
        "Error: SECURE_TEE_DROM_SIZE must be a multiple of MMU_PAGE_SIZE (CONFIG_MMU_PAGE_SIZE)!");
