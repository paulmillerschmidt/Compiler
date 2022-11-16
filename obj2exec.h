#include <iostream>
#include <elfio/elfio.hpp>

/* Segment IDs for 4 main program segments */
enum SEGMENT_ID {
  SEG_TEXT,
  SEG_RODATA,
  SEG_DATA,
  SEG_BSS,
  SEG_COUNT
};

/* Section IDs for 4 main program sections */
enum SECTION_ID {
  SEC_TEXT,
  SEC_RODATA,
  SEC_DATA,
  SEC_BSS,
  SEC_COUNT
};

/* Struct to store info about a particular main section */
struct main_section_info {
  int idx;                // Section index
  ELFIO::Elf_Xword sz;    // Section size
  ELFIO::Elf_Xword align; // Section alignment
};

/* Information about source object file */
struct source_info {
  // Store properties of the main program sections
  main_section_info main_sections[SEC_COUNT];

  int rela_text_idx;  // Index of text relocation section in original file

  int symtab_idx;     // Index of symbol table in original file
  int strtab_idx;     // Index of string table (used by symbol table) in orig f
};

/* Information about destination object file */
struct dest_info {
  // Pointers to destination object file main section objects
  ELFIO::section* sec_ptr[SEC_COUNT];

  // Pointers to destination object file main segment objects
  ELFIO::segment* seg_ptr[SEG_COUNT];

  ELFIO::section* symtab_sec; // Pointer to symbol table section
  ELFIO::section* strtab_sec; // Pointer to string table section (used by symtab)
};

/* Representation of a memory segment */
struct memory_map_segment {
  ELFIO::Elf64_Addr vaddr;
  ELFIO::Elf_Xword  size;
  ELFIO::Elf_Word   flags;
  ELFIO::Elf_Xword  align;
};

/* Memory map consisting of all memory segments */
struct memory_map {
  memory_map_segment segments[SEG_COUNT];
};

/* Find sections in the source object file */
int find_sections(ELFIO::elfio* reader, source_info* src_info);

/* Plan the memory layout for the executable */
int generate_memory_map(const source_info* src_info, memory_map* mm);

/* Initialize the output executable file */
ELFIO::elfio prepare_output_file(ELFIO::elfio* reader);

/* Prepare the sections and segments within the executable */
int prepare_exec_skeleton(ELFIO::elfio* writer, dest_info* dst_info,
                          const source_info* src_info, const memory_map* mm);

/* Create a new symbol table for use with the executable */
int create_symbol_table(ELFIO::elfio* writer, ELFIO::elfio* reader,
                        const source_info* src_info, dest_info* dst_info,
                        const memory_map* mm);

/* Copy the contents of sections from the object file to the executable */
int copy_main_sections(ELFIO::elfio* writer, ELFIO::elfio* reader,
                       const source_info* src_info, dest_info* dst_info);

/* Perform relocations within the .text segment */
int relocate_text_segment(ELFIO::elfio* writer, ELFIO::elfio* reader,
                          const source_info* src_info, dest_info* dst_info,
                          const memory_map* mm);

/* Find and set the entry point of the executable to the _start function */
int set_entry_point(ELFIO::elfio* writer, const dest_info* dst_info);

/* Error codes for program */
enum ERROR_CODES {
  E_SUCCESS = 0,
  E_ARGS,
  E_LOAD_SRC,
  E_SRC_NOT_RELOCATABLE,
  E_FIND_SECTIONS,
  E_GENERATE_MEMORY_MAP,
  E_PREPARE_EXEC_SKELETON,
  E_CREATE_SYMBOL_TABLE,
  E_COPY_MAIN_SECTIONS,
  E_RELOCATE_TEXT_SEGMENT,
  E_SET_ENTRY_POINT,
  E_WRITE_OUTPUT,
  E_ALLOCATE_MEMORY_MAP,
  E_MAX
};

/************************************
  Start of loader specific functions 
************************************/

/* Allocate memory to run the executable and set the memory map accordingly */
int allocate_memory_map(const source_info* info, memory_map* mm);

/* Load and run the executable */
int load(ELFIO::elfio* writer, dest_info* dst_info, memory_map* mm);

