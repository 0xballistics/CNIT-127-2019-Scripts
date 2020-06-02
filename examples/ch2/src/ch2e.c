#include <stdio.h>

void user_input(){
    char buf[30];
    gets(buf);
    printf("%s\n", buf);
}

int main(){
    user_input();
    return 0;
}
