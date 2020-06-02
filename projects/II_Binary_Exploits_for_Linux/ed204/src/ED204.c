#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv){
        char buf[1024];

	if ( argc != 2) {
		printf("Usage: %s string\n", argv[0]);
		exit(0);
	}

        strcpy(buf, argv[1]);
        printf(buf);
        printf("\n");
        exit(0);
}
