#include <unistd.h>

int main(){
    char* shell[2];
    shell[0] = "/bin/bash";
    shell[1] = NULL;
    execve(shell[0], shell, NULL);
}
