char shellcode[] = "\xbb\x00\x00\x00\x00"
                   "\xb8\x01\x00\x00\x00"
                   "\xcd\x80";

int main(){
    int (*func)();
    func = (int (*)() ) shellcode;
    (int) (*func)();
    return 0;
}
