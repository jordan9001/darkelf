# darkelf
Infects an elf64

This program will take a standard elf64 binary, and give it a new main. The new main will load a shared object of the users choice, and run an exported function before it returns to the original main.

Note, this is a proof of concept, and does not cover a lot of edge cases!
If you want to actually be sneaky, don't use this as is!
This does not handle PIE binaries right now.

possible later TODO:
	do our own dlopen/dlsym (fixes PIE as well)
