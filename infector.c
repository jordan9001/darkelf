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
#define ELF_HEAD_SIZE			0x40
#define ELF_SECTION_VADDR		0x10
#define ELF_SECTION_FILEOFF		0x18
#define ELF_SECTION_SIZE		0x20

#define START_MOV_CODE			((char[]){0x48, 0xc7, 0xc7})
#define START_MOV_LEN			3 

// helpful type
typedef uint64_t offset_t;

// static helper functions
static void print_usage();
static int open_and_map(char* fname, uint8_t** data, size_t* len);
static void** find_arg_main(uint8_t* elf);

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

void** find_arg_main(uint8_t* elf_base) {
	uint8_t type;
	offset_t startoff;
	offset_t section_off;
	uint16_t section_entry_size;
	uint16_t section_entry_count;
	uint8_t* cursor;
	int i;
	offset_t section_vaddr;
	offset_t section_size;
	offset_t text_file_offset = 0;
	
	// first find the _start
	// 1 == 32, 2 == 64
	type = elf_base[ELF_HEAD_TYPE_OFFSET];

	if (type == 1) {
		printf("32 bit elf files unsupported\n");
		return NULL;
	}

	// get the entry pointer (which is an offset to us)
	startoff = *((offset_t*)(elf_base + ELF_HEAD_ENTRY_OFFSET));

	printf("Found _start at %p\n", (void*)startoff);

	// parse the section entries for .text
	section_off = (*(offset_t*)(elf_base + ELF_HEAD_SHOFF_OFFSET));
	section_entry_size = *((uint16_t*)(elf_base + ELF_HEAD_SHENTSIZE_OFFSET));
	section_entry_count = *((uint16_t*)(elf_base + ELF_HEAD_SHNUM_OFFSET));

	cursor = elf_base + section_off;

	// go through the symbol table
	// we don't want to go looking for section strings, because those can be stripped
	// so we will check for the section that contains our _start
	for (i = 0; i < section_entry_count; i++, cursor += section_entry_size) {
		section_vaddr = *((offset_t*)(cursor + ELF_SECTION_VADDR));
		section_size = *((offset_t*)(cursor + ELF_SECTION_SIZE));
		if (section_vaddr <= startoff && (section_vaddr + section_size) > startoff) {
			text_file_offset = *((offset_t*)(cursor + ELF_SECTION_FILEOFF));
			break;
		}
	}

	if (!text_file_offset) {
		// we didin't find the section
		printf("Couldn't find section for _start!\n");
		return NULL;
	}

	startoff = (startoff - section_vaddr) + text_file_offset;
	cursor = elf_base + startoff;
	
	printf("Start in the file should be at offset %p\n", (void*)startoff);
	printf("First few bytes : %02x %02x %02x %02x\n", cursor[0], cursor[1], cursor[2], cursor[3]); 

	// we have the section, now we need to find mov rdi, main before the call to __libc_start_main
	// so in most x86-64 elf files the mov is a REX.W mov, so the instruction starts with 3 bytes
	// 48 c7 c7 
	// we really should use a length disassembler

	while (1) {
		if (!memcmp(cursor, START_MOV_CODE, START_MOV_LEN)) {
			break;
		}
		cursor++;
		if (cursor >= (elf_base + startoff + section_size)) {
			// we didn't find it :(
			return NULL;
		}
	}
	
	cursor += START_MOV_LEN;	

	return (void**)cursor;
}

int do_infect(char* target_path, char* lib_path, char* exported_func) {
	int tfd;
	uint8_t* tdata;
	size_t tdata_len;
	void** arg_main;
	// open and map target
	tfd = open_and_map(target_path, &tdata, &tdata_len);

	// find original main
	// it will be an argument to __libc_start_main
	arg_main = find_arg_main(tdata);
	if (arg_main == NULL) {
		printf("Couldn't find main as an arg\n");
		close(tfd);
		return -1;
	}

	printf("Is main at %p?\n", *arg_main);

	//TODO
	// find area for our new main

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

	do_infect(argv[1], argv[2], argv[3]);
	
	return 0;

}
