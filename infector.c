// this will take a elf64 and insert in a new main to run before the real main
// the new main will load a library and call into it

#include <stdin.h>

// static helper functions
static void print_usage();

void print_usage(char* progname) {
	printf("Usage : %s /path/to/elf /path/to/lib exported_func\n", progname);
}

int main(int argc, char** argv) {
	
	if (argc < 4) {
		print_usage(argv[0]);
		exit(-1);
	}

	// open and map target

	// find original main

	// find area for our new main

	// put in our new main

	// overwrite original main pointer
	
	return 0;
}
