# darkelf
Infects an elf64

This program will take a standard elf64 binary, and give it a new main. The new main will load a shared object of the users choice, and run an exported function before it returns to the original main.
