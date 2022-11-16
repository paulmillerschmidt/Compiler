#include "obj2exec.h"

#include "limits.h"
#include "stdio.h"

// Uncomment the following line to enable lprintf(...) macros
#define L_DEBUG


#ifdef L_DEBUG
  #define lprintf(...) fprintf(stderr, "[LD] " __VA_ARGS__)
#else
  #define lprintf(...)
#endif

// Import symbols from "ELFIO" namespace
using namespace ELFIO;

// The first pass in our linker finds the various sections as defined
// Returns 0 if successful, -1 otherwise
int find_sections(elfio* reader, source_info* src_info)
{
  memset(src_info, 0, sizeof(*src_info));

  // Fill in the source_info struct by going through each section
  Elf_Half sec_num = reader->sections.size();

  // We perform a number of passes to fill in the data structure. The first
  // pass fills in the section index of the main sections: .text, .data, .bss
  // and .rodata
  for (int i = 0; i < sec_num; i++) {
    section* psec = reader->sections[i];
    if (psec->get_type() == SHT_PROGBITS) {
      if (psec->get_name() == ".text") {
        if (src_info->main_sections[SEC_TEXT].idx == 0) {
          src_info->main_sections[SEC_TEXT].idx   = i;
          src_info->main_sections[SEC_TEXT].sz    = psec->get_size();
          src_info->main_sections[SEC_TEXT].align = psec->get_addr_align();
        }
        else {
          lprintf("More than one .text segment defined in input!\n");
          return -1;
        }
      }
      if (psec->get_name() == ".data") {
        if (src_info->main_sections[SEC_DATA].idx == 0) {
          src_info->main_sections[SEC_DATA].idx   = i;
          src_info->main_sections[SEC_DATA].sz    = psec->get_size();
          src_info->main_sections[SEC_DATA].align = psec->get_addr_align();
        }
        else {
          lprintf("More than one .data segment defined in input!\n");
          return -1;
        }
      }
      if (psec->get_name() == ".rodata") {
        if (src_info->main_sections[SEC_RODATA].idx == 0) {
          src_info->main_sections[SEC_RODATA].idx   = i;
          src_info->main_sections[SEC_RODATA].sz    = psec->get_size();
          src_info->main_sections[SEC_RODATA].align = psec->get_addr_align();
        }
        else {
          lprintf("More than one .rodata segment defined in input!\n");
          return -1;
        }
      }
    }
    if (psec->get_type() == SHT_NOBITS) {
      if (psec->get_name() == ".bss") {
        if (src_info->main_sections[SEC_BSS].idx == 0) {
          src_info->main_sections[SEC_BSS].idx   = i;
          src_info->main_sections[SEC_BSS].sz    = psec->get_size();
          src_info->main_sections[SEC_BSS].align = psec->get_addr_align();
        }
        else {
          lprintf("More than one .bss segment defined in input!\n");
          return -1;
        }
      }
    }
  }

  // The second pass fills in the text relocation, symbol and string tables. We
  // need to perform this after the first pass, since we don't know which
  // section is which beforehand.
  for (int i = 0; i < sec_num; i++) {
    section* psec = reader->sections[i];
    if (psec->get_type() == SHT_RELA) {
      // This is a relocation section, but is it for the text section?
      if (psec->get_info() == src_info->main_sections[SEC_TEXT].idx) {
        if (src_info->rela_text_idx == 0) {
          // Update the struct
          src_info->rela_text_idx = i;

          // We can get the index of the symbol table, which is stored in the
          // sh_link field
          src_info->symtab_idx = psec->get_link();

          // The symbol table in turn contains a link to the string table in
          // the sh_link field
          section *pstrtab = reader->sections[src_info->symtab_idx];
          src_info->strtab_idx = pstrtab->get_link();
        }
        else {
          lprintf("More than one .rela.text segment defined in input!\n");
          return -1;
        }
      }
      else {
        // We only handle relocating the text segment for now
        lprintf("Only .text segments can be relocated!\n");
        return -1;
      }
    }
  }

  return 0;
}

ELFIO::Elf64_Addr get_next_vaddr(ELFIO::Elf64_Addr curr_address, uint64_t page_size) {

  if (curr_address % page_size == 0) {
    return curr_address;
  }
  else {
    return curr_address + (page_size - (curr_address % page_size));
  }

}

// The second pass in our linker generates a memory map of where each section
// should be loaded in memory
int generate_memory_map(const source_info* info, memory_map* mm)
{
  /*
   * This function prepares a memory map for the linker program. Ultimately,
   * this memory will be used to generate the various ELF segments once the
   * linking process has finished.
   *
   * This function will fill in the memory_map* mm struct, by completing every
   * field in every member of the mm->segments[] array. Members of the 
   * SEGMENT_ID enum should be used to index the array by the segment name.
   *
   * It is up to you to pick a virtual address to assign to each segment's 
   * starting virtual address (vaddr). However, there are several restrictions
   * that you must follow which are described in the Requirements section of 
   * the assignment notes.
   *
   * It is also up to you to make sure that the flags and align fields are
   * correctly set up for each segment. The align fields should be set to the
   * system page size so that the OS can load the program correctly when it is
   * run.
   */

  uint64_t page_size = 0x1000;
  ELFIO::Elf64_Addr curr_vaddr = 0x400000;

  mm->segments[SEG_TEXT].size   = info->main_sections[SEC_TEXT].sz;
  mm->segments[SEG_RODATA].size = info->main_sections[SEC_RODATA].sz;
  mm->segments[SEG_DATA].size   = info->main_sections[SEC_DATA].sz;
  mm->segments[SEG_BSS].size    = info->main_sections[SEC_BSS].sz;

  if (mm->segments[SEG_TEXT].size > 0) {
    mm->segments[SEG_TEXT].vaddr = curr_vaddr;
    curr_vaddr += mm->segments[SEG_TEXT].size;
    mm->segments[SEG_TEXT].align   = page_size;
    mm->segments[SEG_TEXT].flags = PF_X | PF_R;

  }  

  if (mm->segments[SEG_RODATA].size > 0) {
    mm->segments[SEG_RODATA].align = page_size;
    curr_vaddr = get_next_vaddr(curr_vaddr, page_size);
    mm->segments[SEG_RODATA].vaddr = curr_vaddr;
    curr_vaddr += mm->segments[SEG_RODATA].size;
    mm->segments[SEG_RODATA].flags = PF_R;
  }

  if (mm->segments[SEG_DATA].size > 0) {
    mm->segments[SEG_DATA].align   = page_size;
    curr_vaddr = get_next_vaddr(curr_vaddr, page_size);
    mm->segments[SEG_DATA].vaddr = get_next_vaddr(curr_vaddr, page_size);
    curr_vaddr += mm->segments[SEG_DATA].size;
    mm->segments[SEG_DATA].flags = PF_W | PF_R;
  }

  if (mm->segments[SEG_BSS].size > 0) {
    mm->segments[SEG_BSS].align    = page_size;
    curr_vaddr = get_next_vaddr(curr_vaddr, page_size);
    mm->segments[SEG_BSS].vaddr = curr_vaddr;
    curr_vaddr += mm->segments[SEG_BSS].size;
    mm->segments[SEG_BSS].flags = PF_W | PF_R;
  }

  

  // TODO: set up vaddrs, flags and alignment for every segment with non-zero
  // size.

  
  





  

  return 0;
}

// Prepare an executable output file with the same machine/encoding as input
// file
elfio prepare_output_file(elfio* reader)
{
  elfio writer;
  
  writer.create(reader->get_class(), reader->get_encoding());
  writer.set_os_abi(0);
  writer.set_machine(reader->get_machine());
  writer.set_type(ET_EXEC);
  writer.set_flags(0);

  return writer;
}

// Prepare a skeleton of the executable file with sections and segments but no
// data
int prepare_exec_skeleton(elfio* writer, dest_info* dst_info,
                          const source_info* info, const memory_map* mm)
{
  // Add .text section
  dst_info->sec_ptr[SEC_TEXT] = writer->sections.add(".text");
  if (!dst_info->sec_ptr[SEC_TEXT]) {
    lprintf("Couldn't create .text section in executable.\n");
    return -1;
  }
  
  // .text section contains data only used by program (not by linker/loader)
  dst_info->sec_ptr[SEC_TEXT]->set_type(SHT_PROGBITS);
  
  // .text section is allocated in memory and executable (but not writeable)
  dst_info->sec_ptr[SEC_TEXT]->set_flags(SHF_ALLOC | SHF_EXECINSTR);

  dst_info->sec_ptr[SEC_TEXT]->set_addr_align(info->main_sections[SEC_TEXT].align);

  // .text segment has an in-memory virtual address
  dst_info->sec_ptr[SEC_TEXT]->set_address(mm->segments[SEG_TEXT].vaddr);

  // Add memory segment for .text section
  dst_info->seg_ptr[SEG_TEXT] = writer->segments.add();
  dst_info->seg_ptr[SEG_TEXT]->set_type(PT_LOAD);
  dst_info->seg_ptr[SEG_TEXT]->set_virtual_address(mm->segments[SEG_TEXT].vaddr);
  dst_info->seg_ptr[SEG_TEXT]->set_physical_address(mm->segments[SEG_TEXT].vaddr);
  dst_info->seg_ptr[SEG_TEXT]->set_flags(mm->segments[SEG_TEXT].flags);
  dst_info->seg_ptr[SEG_TEXT]->set_align(mm->segments[SEG_TEXT].align);

  // Link the text segment to the corresponding section(s)
  dst_info->seg_ptr[SEG_TEXT]->add_section_index(
      dst_info->sec_ptr[SEC_TEXT]->get_index(), dst_info->sec_ptr[SEC_TEXT]->get_addr_align());

  // Add .rodata section
	if (mm->segments[SEG_RODATA].size > 0) {
		dst_info->sec_ptr[SEC_RODATA] = writer->sections.add(".rodata");
		if (!dst_info->sec_ptr[SEC_RODATA]) {
			lprintf("Couldn't create .rodata section in executable.\n");
			return -1;
		}

		// .rodata section contains data only used by program
		dst_info->sec_ptr[SEC_RODATA]->set_type(SHT_PROGBITS);

		// .rodata section is allocated in memory and read-only
		dst_info->sec_ptr[SEC_RODATA]->set_flags(SHF_ALLOC);

		dst_info->sec_ptr[SEC_RODATA]->set_addr_align(info->main_sections[SEC_RODATA].align);

		dst_info->sec_ptr[SEC_RODATA]->set_address(mm->segments[SEG_RODATA].vaddr);

		// Add memory segment for .rodata section
		dst_info->seg_ptr[SEG_RODATA] = writer->segments.add();
		dst_info->seg_ptr[SEG_RODATA]->set_type(PT_LOAD);
		dst_info->seg_ptr[SEG_RODATA]->set_virtual_address(mm->segments[SEG_RODATA].vaddr);
		dst_info->seg_ptr[SEG_RODATA]->set_physical_address(mm->segments[SEG_RODATA].vaddr);
		dst_info->seg_ptr[SEG_RODATA]->set_flags(mm->segments[SEG_RODATA].flags);
		dst_info->seg_ptr[SEG_RODATA]->set_align(mm->segments[SEG_RODATA].align);

		// Link the rodata segment to the corresponding section(s)
		dst_info->seg_ptr[SEG_RODATA]->add_section_index(
				dst_info->sec_ptr[SEC_RODATA]->get_index(), dst_info->sec_ptr[SEC_RODATA]->get_addr_align());
	}

  // Add .data section and segment
  if(mm->segments[SEG_DATA].size > 0) {
    dst_info->sec_ptr[SEC_DATA] = writer->sections.add(".data");
    if (!dst_info->sec_ptr[SEC_DATA]) {
      lprintf("Couldn't create .data section in executable.\n");
      return -1;
    }

    // .data section is PROGBITS, allocated and read/write
    dst_info->sec_ptr[SEC_DATA]->set_type(SHT_PROGBITS);
    dst_info->sec_ptr[SEC_DATA]->set_flags(SHF_ALLOC | SHF_WRITE);
    dst_info->sec_ptr[SEC_DATA]->set_addr_align(info->main_sections[SEC_DATA].align);
    dst_info->sec_ptr[SEC_DATA]->set_address(mm->segments[SEG_DATA].vaddr);

    // Add corresponding memory segment
    dst_info->seg_ptr[SEG_DATA] = writer->segments.add();
    dst_info->seg_ptr[SEG_DATA]->set_type(PT_LOAD);
    dst_info->seg_ptr[SEG_DATA]->set_virtual_address(mm->segments[SEG_DATA].vaddr);
    dst_info->seg_ptr[SEG_DATA]->set_physical_address(mm->segments[SEG_DATA].vaddr);
    dst_info->seg_ptr[SEG_DATA]->set_flags(mm->segments[SEG_DATA].flags);
    dst_info->seg_ptr[SEG_DATA]->set_align(mm->segments[SEG_DATA].align);

    // Link the segment to the section
    dst_info->seg_ptr[SEG_DATA]->add_section_index(
        dst_info->sec_ptr[SEC_DATA]->get_index(), dst_info->sec_ptr[SEC_DATA]->get_addr_align());
  }

  // Add .bss section and segment
  if(mm->segments[SEG_BSS].size > 0) {
    dst_info->sec_ptr[SEC_BSS] = writer->sections.add(".bss");
    if (!dst_info->sec_ptr[SEC_BSS]) {
      lprintf("Couldn't create .bss section in executable.\n");
      return -1;
    }

    // .bss section is NOBITS, allocated and read/write
    dst_info->sec_ptr[SEC_BSS]->set_type(SHT_NOBITS);
    dst_info->sec_ptr[SEC_BSS]->set_flags(SHF_ALLOC | SHF_WRITE);
    dst_info->sec_ptr[SEC_BSS]->set_addr_align(info->main_sections[SEC_BSS].align);
    dst_info->sec_ptr[SEC_BSS]->set_address(mm->segments[SEG_BSS].vaddr);

    // Add corresponding memory segment
    dst_info->seg_ptr[SEG_BSS] = writer->segments.add();
    dst_info->seg_ptr[SEG_BSS]->set_type(PT_LOAD);
    dst_info->seg_ptr[SEG_BSS]->set_virtual_address(mm->segments[SEG_BSS].vaddr);
    dst_info->seg_ptr[SEG_BSS]->set_physical_address(mm->segments[SEG_BSS].vaddr);
    dst_info->seg_ptr[SEG_BSS]->set_flags(mm->segments[SEG_BSS].flags);
    dst_info->seg_ptr[SEG_BSS]->set_align(mm->segments[SEG_BSS].align);
    dst_info->seg_ptr[SEG_BSS]->set_file_size(0);
    dst_info->seg_ptr[SEG_BSS]->set_memory_size(mm->segments[SEG_BSS].size);

    // Link the segment to the section
    dst_info->seg_ptr[SEG_BSS]->add_section_index(
        dst_info->sec_ptr[SEC_BSS]->get_index(), dst_info->sec_ptr[SEC_BSS]->get_addr_align());
  }

  return 0;
}

// Create the symbol table with virtual addresses for the executable
int create_symbol_table(elfio* writer, elfio* reader, 
      const source_info* src_info, dest_info* dst_info, const memory_map* mm)
{
  // Find the symbol table in the object file
  section* src_symtab = reader->sections[src_info->symtab_idx];

  // Create a corresponding symbol and string table section in the destination file
  dst_info->symtab_sec = writer->sections.add(".symtab");
  dst_info->strtab_sec = writer->sections.add(".strtab");
  
  // Symbol table refers to strings in .strtab section
  dst_info->symtab_sec->set_link(dst_info->strtab_sec->get_index());
  
  // Fill in symbol table properties
  dst_info->symtab_sec->set_type(SHT_SYMTAB);
  dst_info->symtab_sec->set_addr_align(8);
  dst_info->symtab_sec->set_entry_size(0x18);
  lprintf("Assuming 24B symbol table entries...\n");

  // Fill in string table properties
  dst_info->strtab_sec->set_type(SHT_STRTAB);

  // Write symbols into new symbol table by converting symbols in source table
  // into virtual addresses
  symbol_section_accessor source_symbols(*reader, src_symtab);
  Elf_Xword sym_num = source_symbols.get_symbols_num();

  symbol_section_accessor dest_symbols(*writer, dst_info->symtab_sec);
  string_section_accessor dest_strings(dst_info->strtab_sec);

  // Add the section symbols. In the symbol table, all local symbols must come
  // before any global symbols, so we need to add these symbols here instead of
  // later on.
  
  // Add section symbol for .text section
  dest_symbols.add_symbol(dest_strings, "", mm->segments[SEG_TEXT].vaddr, 0, STB_LOCAL, 
                          STT_SECTION, 0, dst_info->sec_ptr[SEC_TEXT]->get_index());

  // Add section symbol for .rodata section
  if (mm->segments[SEG_RODATA].size > 0) {
		dest_symbols.add_symbol(dest_strings, "", mm->segments[SEG_RODATA].vaddr, 0, STB_LOCAL,
														STT_SECTION, 0, dst_info->sec_ptr[SEC_RODATA]->get_index());
  }

	// Add section symbol for .data section
  if (mm->segments[SEG_DATA].size > 0) {
    dest_symbols.add_symbol(dest_strings, "", mm->segments[SEG_DATA].vaddr, 0, STB_LOCAL,
                          STT_SECTION, 0, dst_info->sec_ptr[SEC_DATA]->get_index());
  }

	// Add section symbol for .bss section
  if (mm->segments[SEG_BSS].size > 0) {
    dest_symbols.add_symbol(dest_strings, "", mm->segments[SEG_BSS].vaddr, 0, STB_LOCAL,
                          STT_SECTION, 0, dst_info->sec_ptr[SEC_BSS]->get_index());
  }

  for (Elf_Xword i = 0; i < sym_num; i++) {
    // Variables to store symbol properties
    std::string name;
    Elf64_Addr value;
    Elf_Xword size;
    unsigned char bind;
    unsigned char type;
    Elf_Half shndx;
    unsigned char other;

    // Read from source
    source_symbols.get_symbol(i, name, value, size, bind, type, shndx, other);

    switch (type) {
      case STT_NOTYPE:
        // We cannot handle STT_NOTYPE symbols, so just ignore them
        lprintf("Warning: encountered STT_NOTYPE symbol in source\n");
        break;

      case STT_OBJECT:
        // The value and new section indexes of these symbols depend on where
        // the object is located.
        if (shndx == src_info->main_sections[SEC_RODATA].idx) {
          value += mm->segments[SEG_RODATA].vaddr;
          shndx = dst_info->sec_ptr[SEC_RODATA]->get_index();
        }
        else {
          if (shndx == src_info->main_sections[SEC_DATA].idx) {
            value += mm->segments[SEG_DATA].vaddr;
            shndx = dst_info->sec_ptr[SEC_DATA]->get_index();
          }
          else {
            if (shndx == src_info->main_sections[SEC_BSS].idx) {
              value += mm->segments[SEG_BSS].vaddr;
              shndx = dst_info->sec_ptr[SEC_BSS]->get_index();
            }
            else {
              lprintf("Unknown STT_OBJECT section\n");
              return -1;
            }
          }
        }

        // Add to destination table
        dest_symbols.add_symbol(dest_strings, name.c_str(), value, size, 
            bind, type, other, shndx);
        break;

      case STT_FUNC:
        // These symbols are associated with functions/executable code
        if (shndx != src_info->main_sections[SEC_TEXT].idx) {
          lprintf("Function symbols must be associated with .text section\n");
          return -1;
        }
        
        // Adjust to virtual address
        value += mm->segments[SEG_TEXT].vaddr;
        
        // Point to the current text section
        shndx = dst_info->sec_ptr[SEC_TEXT]->get_index();

        // Add to destination table
        dest_symbols.add_symbol(dest_strings, name.c_str(), value, size, 
            bind, type, other, shndx);
        break;

      case STT_SECTION:
        // These symbols refer to the start of sections
        // Since the destination file uses new sections, we do not copy these
        // over
        break;

      case STT_FILE:
        // These symbols are associated with filenames - we don't modify these
        dest_symbols.add_symbol(dest_strings, name.c_str(), value, size, 
            bind, type, other, shndx);
        break;
    }
  }

  // Find one past the end of the index of the last LOCAL entry in the new
  // symbol table - this is required for the sh_info field of the symbol
  // table's section header
  Elf_Xword last_local = 0;
  for (Elf_Xword i = 0; i < dest_symbols.get_symbols_num(); i++) {
    std::string name;
    Elf64_Addr value;
    Elf_Xword size;
    unsigned char bind;
    unsigned char type;
    Elf_Half shndx;
    unsigned char other;

    source_symbols.get_symbol(i, name, value, size, bind, type, shndx, other);
    if (type != STB_LOCAL) {
      last_local = i + 1;
    }
    else {
      // Make sure we don't have an interleaving of STB_LOCAL with other types
      if (last_local != 0) {
        lprintf("Interleaving of LOCAL and non-LOCAL symbols\n");
        return -1;
      }
    }
  }

  // Finalize the symbol table section header
  dst_info->symtab_sec->set_info(last_local);

  return 0;
}

// Copy .text and .rodata segments from source to executable, without
// relocating. Also sets section sizes.
int copy_main_sections(elfio* writer, elfio* reader, \
                       const source_info* src_info, dest_info* dst_info)
{
  // Copy over the .text segment
  section* src_text_sec = reader->sections[src_info->main_sections[SEC_TEXT].idx];
  dst_info->sec_ptr[SEC_TEXT]->set_data(src_text_sec->get_data(), src_text_sec->get_size());
  dst_info->sec_ptr[SEC_TEXT]->set_size(src_info->main_sections[SEC_TEXT].sz);

  // Copy over the .rodata segment
	if (src_info->main_sections[SEC_RODATA].sz > 0) {
		section* src_rodata_sec = reader->sections[src_info->main_sections[SEC_RODATA].idx];
		dst_info->sec_ptr[SEC_RODATA]->set_data(src_rodata_sec->get_data(), src_rodata_sec->get_size());
    dst_info->sec_ptr[SEC_RODATA]->set_size(src_info->main_sections[SEC_RODATA].sz);
	}
  
  // Copy over the .data segment
  if (src_info->main_sections[SEC_DATA].sz > 0) {
    section* src_data_sec = reader->sections[src_info->main_sections[SEC_DATA].idx];
    dst_info->sec_ptr[SEC_DATA]->set_data(src_data_sec->get_data(), src_data_sec->get_size());
    dst_info->sec_ptr[SEC_DATA]->set_size(src_info->main_sections[SEC_DATA].sz);
  }

  // .bss segment requires no copying
  if (src_info->main_sections[SEC_BSS].sz > 0) {
    dst_info->sec_ptr[SEC_BSS]->set_size(src_info->main_sections[SEC_BSS].sz);
  }

  return 0;
}

// Relocate the .text segment in the executable using the symbol table
int relocate_text_segment(elfio* writer, elfio* reader,
      const source_info* src_info, dest_info* dst_info, const memory_map* mm)
{
  if (!src_info->rela_text_idx) {
    lprintf("Cannot perform relocations with no .rela.text section\n");
    return -1;
  }

  // Access the relocation table in the original file
  section* src_rela_sec = reader->sections[src_info->rela_text_idx];
  relocation_section_accessor relocations(*reader, src_rela_sec);

  // Access the original symbol table
  symbol_section_accessor old_symbols(*reader, reader->sections[src_info->symtab_idx]);

  // Access the new symbol table to find values
  symbol_section_accessor new_symbols(*writer, dst_info->symtab_sec);

  // Create a local copy of the .text section, which we will update
  char* textbuf = (char*) malloc(src_info->main_sections[SEC_TEXT].sz);
  if (!textbuf) {
    lprintf("Couldn't allocate buffer to manipulate .text segment\n");
    return -1;
  }
  section* src_text_sec = reader->sections[src_info->main_sections[SEC_TEXT].idx];
  memcpy(textbuf, src_text_sec->get_data(), src_info->main_sections[SEC_TEXT].sz);

  // Iterate through list of relocations
  for (Elf_Xword i = 0; i < relocations.get_entries_num(); i++) {
    Elf64_Addr offset;
    Elf_Word symbol;
    Elf_Word type;
    Elf_Sxword addend;

    relocations.get_entry(i, offset, symbol, type, addend);

    // Find the value of the symbol
    std::string sym_name;
    Elf64_Addr sym_value;
    Elf_Xword sym_size;
    unsigned char sym_bind;
    unsigned char sym_type;
    Elf_Half sym_shndx;
    unsigned char sym_other;

    // Get the name from the OLD symbol table, since relocation entries still
    // use the old symbol table

    //lprintf("Getting symbol #%d\n", symbol);
    old_symbols.get_symbol(symbol, sym_name, sym_value, sym_size, 
        sym_bind, sym_type, sym_shndx, sym_other);
    //lprintf("  symbol name = %s\n", sym_name.c_str());

    // Look up the value in the new symbol table
    new_symbols.get_symbol(sym_name, sym_value, sym_size, sym_bind, \
                           sym_type, sym_shndx, sym_other);

    // Calculate the value of the program counter when this instruction gets
    // executed - this value is used by some addressing modes
    Elf64_Addr pc = mm->segments[SEG_TEXT].vaddr + offset;

    // Calculate the value to update the text segment with
    Elf_Xword value = 0;
    int valsize = 0; // size of value in # bytes

    // lprintf("Relocation using symbol %s = 0x%lx\n", sym_name.c_str(), sym_value);
    // lprintf("  (type = %x, offset = %lx, addend = %ld) \n", type, offset, addend);

    switch (type) {
      case R_X86_64_PC32: {
        uint32_t v = sym_value + addend - pc;
        value = v;
        valsize = 4;
        }; break;

      case R_X86_64_PLT32: {
        // Normally, we would generate a procedure linkage table (PLT), and use
        // the offset to the PLT in this type of relocation. However, since all
        // functions are statically linked, we instead use the value of the
        // destination address directly.
        uint32_t v = sym_value + addend - pc;
        value = v;
        valsize = 4;
        }; break;

      case R_X86_64_32S: {
				int64_t v = sym_value + addend;
        if (v > INT_MAX || v < INT_MIN) {
          lprintf("Relocation error: sym_value %lx + addend %lx overflow\n",
                  sym_value, addend);
          return -1;
        }
				value = v;
				valsize = 4;
        }; break;

			case R_X86_64_32: {
				uint64_t v = sym_value + addend;
        if (v > UINT_MAX) {
          lprintf("Relocation error: sym_value %lx + addend %lx overflow\n",
                  sym_value, addend);
          return -1;
        }
				value = v;
				valsize = 4;
			  }; break;

      default:
        lprintf("Unsupported relocation type %x\n", type);
        free(textbuf);
        return -1;       
    }

    // Actually update the .text section
    switch (valsize) {
      case 4:
        *((uint32_t*) ((char*) textbuf + offset)) = (uint32_t) value; 
        break;
      case 8:
        *((Elf_Xword*) ((char*) textbuf + offset)) = value;
        break;
      default:
        lprintf("Unsupported relocation value size %d\n", valsize);
        free(textbuf);
        return -1;
    }

    //lprintf("Writing 0x%lx (%d bytes) to offset 0x%lx in .text\n",
    //    value, valsize, offset);
  }

  // Update the new text section
  dst_info->sec_ptr[SEC_TEXT]->set_data(textbuf, src_info->main_sections[SEC_TEXT].sz);

  // Free the buffer
  free(textbuf);

  lprintf(".text relocation complete\n");
  return 0;
}

// Sets the entry point (virtual address) to _start() function
int set_entry_point(elfio* writer, const dest_info* dst_info)
{
  // Variable to store entry address
  Elf64_Addr entry;

  // Find value of _start symbol
  symbol_section_accessor symbols(*writer, dst_info->symtab_sec);

  // Other variables returned by get_symbol
  Elf_Xword size;
  unsigned char bind;
  unsigned char type;
  Elf_Half section_index;
  unsigned char other;

  if (symbols.get_symbol("_start", entry, size, bind, type, section_index, other)) {
    lprintf("Found _start = %lx\n", entry);
  }
  else {
    lprintf("Unable to find _start in program.\n");
    return -1;
  }

  writer->set_entry(entry);

  return 0;
}

int main(int argc, char* argv[])
{
  char *ipath, *opath;
  int exec = 0;
  int bad_args = 0;

  // Parse command line arguments
  if (argc < 3) {
    bad_args = 1;
  }
  else {
    if (strncmp("-x", argv[1], 3) == 0) {
      if (argc < 4) {
        bad_args = 1;
      }
      else {
        exec = 1;
        ipath = argv[2];
        opath = argv[3];
      }
    }
    else {
      ipath = argv[1];
      opath = argv[2];
    }
  }

  if (bad_args) {
    lprintf("Usage: %s [-x] <object file> <executable>\n", argv[0]);
    return E_ARGS;
  }

  // Create elfio reader (source file)
  elfio reader;
  if (!reader.load(ipath)) {
    lprintf("Can't find or process ELF file %s\n", ipath);
    return E_LOAD_SRC;
  }

  // Perform some sanity checks - firstly, the file type must be relocatable
  if (reader.get_type() != ET_REL) {
    lprintf("Source file not relocatable\n");
    return E_SRC_NOT_RELOCATABLE;
  }

  /* We should also check here for OS/ABI/Machine etc */

  // Find the indices of various sections within the input file
  source_info src_info = {0};
  if (find_sections(&reader, &src_info)) {
    lprintf("Error when finding sections\n");
    return E_FIND_SECTIONS;
  }
  else {
    lprintf("Section Index and Size\n");
    lprintf("----------------------\n");
    lprintf(".text      [%d] %ldB\n", \
      src_info.main_sections[SEC_TEXT].idx, src_info.main_sections[SEC_TEXT].sz);
    lprintf(".data      [%d] %ldB\n", \
      src_info.main_sections[SEC_DATA].idx, src_info.main_sections[SEC_DATA].sz);
    lprintf(".bss       [%d] %ldB\n", \
      src_info.main_sections[SEC_BSS].idx, src_info.main_sections[SEC_BSS].sz);
    lprintf(".rodata    [%d] %ldB\n", \
      src_info.main_sections[SEC_RODATA].idx, src_info.main_sections[SEC_RODATA].sz);
    lprintf(".rela.text [%d]\n"     , src_info.rela_text_idx);
    lprintf(".symtab    [%d]\n"     , src_info.symtab_idx);
    lprintf(".strtab    [%d]\n"     , src_info.strtab_idx);
    lprintf("\n\n");
  }

  // Generate the memory map for the executable
  memory_map mm;
  memset(&mm, 0, sizeof(mm));
  
  if (exec) {
    if (allocate_memory_map(&src_info, &mm)) {
      lprintf("Error allocating memory map\n");
      return E_ALLOCATE_MEMORY_MAP;
    }
  }
  else {
    if (generate_memory_map(&src_info, &mm)) {
      lprintf("Error generating memory map\n");
      return E_GENERATE_MEMORY_MAP;
    }
  }

  // Print the memory map for debugging purposes
  lprintf("Memory Map \n");
  lprintf("-----------------------------------------\n");
  
  lprintf(".text  : %016lx - %016lx\n", \
      mm.segments[SEG_TEXT].vaddr, \
      mm.segments[SEG_TEXT].vaddr + mm.segments[SEG_TEXT].size);
 
	if (mm.segments[SEG_RODATA].size > 0) {
		lprintf(".rodata: %016lx - %016lx\n", \
				mm.segments[SEG_RODATA].vaddr, \
				mm.segments[SEG_RODATA].vaddr + mm.segments[SEG_RODATA].size);
	}

  if (mm.segments[SEG_DATA].size > 0) {
    lprintf(".data  : %016lx - %016lx\n", \
        mm.segments[SEG_DATA].vaddr, 
        mm.segments[SEG_DATA].vaddr + mm.segments[SEG_DATA].size);
  }

  if (mm.segments[SEG_BSS].size > 0) {
    lprintf(".bss   : %016lx - %016lx\n", \
        mm.segments[SEG_BSS].vaddr, 
        mm.segments[SEG_BSS].vaddr + mm.segments[SEG_BSS].size);
  }

  lprintf("\n");

  // Prepare executable output file
  elfio writer = prepare_output_file(&reader);

  // Contains pointers to structures in executable
  struct dest_info dst_info = {0};

  // Add skeleton to output file
  if (prepare_exec_skeleton(&writer, &dst_info, &src_info, &mm)) {
    lprintf("Can't generate executable skeleton\n");
    return E_PREPARE_EXEC_SKELETON;
  }

  // Create the symbol table in the executable
  if (create_symbol_table(&writer, &reader, &src_info, &dst_info, &mm)) {
    lprintf("Can't create symbol table\n");
    return E_CREATE_SYMBOL_TABLE;
  }

  // Copy the (raw) section content from source to executable
  if (copy_main_sections(&writer, &reader, &src_info, &dst_info)) {
    lprintf("Can't copy raw section data\n");
    return E_COPY_MAIN_SECTIONS;
  }

  // Perform relocations
  if (relocate_text_segment(&writer, &reader, &src_info, &dst_info, &mm)) {
    lprintf("Couldn't perform relocations\n");
    return E_RELOCATE_TEXT_SEGMENT;
  }

  // Set entry point to _start() function
  if (set_entry_point(&writer, &dst_info)) {
    lprintf("Couldn't set entry point\n");
    return E_SET_ENTRY_POINT;
  }

  // Write output file
  if (!writer.save(opath)) {
    lprintf("Can't write ELF file %s\n", opath);
    return E_WRITE_OUTPUT;
  }
  else {
    lprintf("Successfully wrote to %s\n", opath);
  }

  if (exec == 1) {
    return load(&writer, &dst_info, &mm);
  }
  else {
    return E_SUCCESS;
  }
}

/****************************
 * Start of loader functions
 ***************************/

// Start of loader functions
#include <errno.h>
#include <sys/mman.h>
#include <string.h>

int allocate_memory_map(const source_info* src_info, memory_map* mm)
{
  /*
   * You can copy much of the source code for this function from
   * generate_memory_map. This time, however, you should allocate memory using
   * mmap inside of this process instead of picking arbritary virtual
   * addresses. A later stage of the loader (that you also help write) will
   * copy the binary data into this process's memory address space.
   *
   * It is up to you how you allocate memory. However, more marks will be
   * awarded if you minimize the number of `mmap` calls. You should also try
   * to minimize the amount of memory that you allocate.
   *
   * Note that you should use `mmap` and not `malloc` or other variants 
   * because you will later protect the memory using mprotect.
   *
   */

  // Copy sizes from src_info to mm
  mm->segments[SEG_TEXT].size   = src_info->main_sections[SEC_TEXT].sz;
  mm->segments[SEG_DATA].size   = src_info->main_sections[SEC_DATA].sz;
  mm->segments[SEG_BSS].size    = src_info->main_sections[SEC_BSS].sz;
  mm->segments[SEG_RODATA].size = src_info->main_sections[SEC_RODATA].sz;

  // TODO: set up vaddrs, flags and alignment for each segment that you use.
  // Hint: For extra marks, see if you can combine more than one segment into
  // the same page (where each segment starts at a different offset within the
  // page so that they don't overlap). Note, however, that you must still
  // be able to enforce read, write and execute permissions correctly.

  //can make these all one?
  void *addr;
  uint64_t page_size = 0x1000;
  ELFIO::Elf64_Addr curr_vaddr = 0x400000;


  if (mm->segments[SEG_TEXT].size > 0) {
    //set vaddrs, flags, alignment
    // mm->segments[SEG_TEXT].vaddr = curr_vaddr;
    mm->segments[SEG_TEXT].align   = src_info->main_sections[SEC_TEXT].align;
    mm->segments[SEG_TEXT].flags = PF_X | PF_R;
    //mmap memory 
    mm->segments[SEG_TEXT].vaddr = (ELFIO::Elf64_Addr) mmap(NULL, mm->segments[SEG_TEXT].size, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_PRIVATE | MAP_32BIT | MAP_ANONYMOUS, -1, 0);
    curr_vaddr = mm->segments[SEG_TEXT].vaddr;
  //   if (mm->segments[SEG_TEXT].vaddr == MAP_FAILED) {
  //     fprintf(stderr, "MMAP FAILED: TEXT");
  //     exit(0);
  // } 
  //update vaddr
  curr_vaddr += mm->segments[SEG_TEXT].size;  

  }  

  if (mm->segments[SEG_RODATA].size > 0) {
    //set vals
    mm->segments[SEG_RODATA].align = src_info->main_sections[SEC_RODATA].align;
    curr_vaddr = get_next_vaddr(curr_vaddr, page_size);
    mm->segments[SEG_RODATA].vaddr = curr_vaddr;
    mm->segments[SEG_RODATA].flags = PF_R;
    //mmap
    mm->segments[SEG_RODATA].vaddr = (ELFIO::Elf64_Addr) mmap((void *) mm->segments[SEG_RODATA].vaddr, mm->segments[SEG_RODATA].size, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_PRIVATE | MAP_32BIT | MAP_ANONYMOUS, -1, 0);
    // if (mm->segments[SEG_RODATA].vaddr == MAP_FAILED) {
    //   fprintf(stderr, "MMAP FAILED: RODATA");
    //   exit(0);
    // }
  //update vaddr
  curr_vaddr += mm->segments[SEG_RODATA].size;
  }

  if (mm->segments[SEG_DATA].size > 0) {
    //set vals
    mm->segments[SEG_DATA].align   = src_info->main_sections[SEC_DATA].align;
    curr_vaddr = get_next_vaddr(curr_vaddr, mm->segments[SEG_DATA].align);
    mm->segments[SEG_DATA].vaddr = get_next_vaddr(curr_vaddr, page_size);
    mm->segments[SEG_DATA].flags = PF_W | PF_R;
    //mmap
    mm->segments[SEG_DATA].vaddr = (ELFIO::Elf64_Addr) mmap((void *) mm->segments[SEG_DATA].vaddr, mm->segments[SEG_DATA].size, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_PRIVATE | MAP_32BIT | MAP_ANONYMOUS, -1, 0);

    // if (mm->segments[SEG_DATA].vaddr == MAP_FAILED) {
    //   fprintf(stderr, "MMAP FAILED: DATA");
    //   exit(0);
    // } 
    //update vaddr
    curr_vaddr += mm->segments[SEG_DATA].size;
  }

  if (mm->segments[SEG_BSS].size > 0) {
    //set vals
    mm->segments[SEG_BSS].align    = src_info->main_sections[SEC_BSS].align;
    curr_vaddr = get_next_vaddr(curr_vaddr, mm->segments[SEG_BSS].align);
    mm->segments[SEG_BSS].vaddr = curr_vaddr;   
    mm->segments[SEG_BSS].flags = PF_W | PF_R;
    //mmap 
    mm->segments[SEG_BSS].vaddr = (ELFIO::Elf64_Addr) mmap((void *) mm->segments[SEG_BSS].vaddr, mm->segments[SEG_BSS].size, PROT_READ | PROT_EXEC | PROT_WRITE, MAP_PRIVATE | MAP_32BIT | MAP_ANONYMOUS, -1, 0);
  //   if (mm->segments[SEG_BSS].vaddr == MAP_FAILED) {
  //     fprintf(stderr, "MMAP FAILED: BSS");
  //     exit(0);
  // } 
    //update vaddr, maybe don't need this 
    // curr_vaddr += mm->segments[SEG_BSS].size;
  }

  



  return 0;
}

int load(ELFIO::elfio* writer, dest_info* dst_info, memory_map* mm)
{
  /*
   * This function loads the binary into the memory that was allocated with
   * allocate_memory_map.
   *
   * We have already written the source code that copies the binary data into
   * memory. However, when we run a program using the loader, we find that 
   * the program can do things that are not allowed in the linked version,
   * such as writing to read only memory!
   *
   * Try running the loader tests (make test-loader) - many of them will fail,
   * even if your allocate_memory_map function is correct. That's because the
   * tests check that certain "undefined" behaviour such as writing to the
   * read-only data segment causes a segfault.
   *
   * You need to protect the various segments that are loading by using the 
   * `mprotect` system call. This system call lets you assign different
   * read-write-execute permissions to different pages. Any accesses to an 
   * mprotect'ed region which do not have sufficient permissions will result
   * in a segfault. This is the same behaviour as when the program runs using
   * the system loader (ld). You may need to codesign both allocate_memory_map
   * and this function in order to correctly set up permissions using mprotect.
   *
   * You can test your implementation with make test-loader. You may also wish
   * to write your own test cases to further stress your implementation,
   * although these will not be assessed.
   */

  // int protection_result;
  // Copy every segment that exists into memory
  if (dst_info->sec_ptr[SEC_TEXT]) {
    void* p = (void*) dst_info->seg_ptr[SEG_TEXT]->get_virtual_address(); 

    mprotect(p, mm->segments[SEG_TEXT].size, PROT_WRITE);
    memcpy(p, dst_info->sec_ptr[SEC_TEXT]->get_data(), dst_info->sec_ptr[SEC_TEXT]->get_size());
    mprotect(p, mm->segments[SEG_TEXT].size, PROT_READ | PROT_EXEC);
    // if (mprotect(p, mm->segments[SEG_TEXT].size, mm->segments[SEG_TEXT].flags != 0)) {
    //   fprintf(stderr, "MPROTECT FAILED: TEXT");
    // exit(0);
    // }
  }
  if (dst_info->sec_ptr[SEC_RODATA]) {
    void* p = (void*) dst_info->seg_ptr[SEG_RODATA]->get_virtual_address();    
    mprotect(p, mm->segments[SEG_RODATA].size, PROT_WRITE);
    memcpy(p, dst_info->sec_ptr[SEC_RODATA]->get_data(), dst_info->sec_ptr[SEC_RODATA]->get_size());
    mprotect(p, mm->segments[SEG_RODATA].size, PROT_READ);
    // if (mprotect(p, mm->segments[SEG_RODATA].size, PROT_READ) != 0) {
    //   fprintf(stderr, "MPROTECT FAILED: RODATA");
    // exit(0);
    // }
  }
  if (dst_info->sec_ptr[SEC_DATA]) {
    void* p = (void*) dst_info->seg_ptr[SEG_DATA]->get_virtual_address();   
    mprotect(p, mm->segments[SEG_DATA].size, PROT_WRITE);
    memcpy(p, dst_info->sec_ptr[SEC_DATA]->get_data(), dst_info->sec_ptr[SEC_DATA]->get_size());
    mprotect(p, mm->segments[SEG_DATA].size, PROT_WRITE | PROT_READ);
    // if (mprotect(p, mm->segments[SEG_DATA].size, PROT_WRITE | PROT_READ) != 0) {
    //   fprintf(stderr, "MPROTECT FAILED: DATA");
    // exit(0);
    //   }
  }

  



  lprintf("Starting program...\n");

  // Jump to start
  int (*func)(void) = (int(*)(void)) writer->get_entry();

  // We don't expect to return from this function - if we do, something has
  // gone wrong (the original program is ill-formed)
  func();

  return -1;
}

