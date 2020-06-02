# assembler:
sudo pacman -S nasm

nasm -f elf32 src/exit.asm
gcc -m32 -o exit_shellcode exit.o

# shellcode compile (start from stack):
gcc -m32 -z execstack -o bin/test_exit src/test_exit.c
