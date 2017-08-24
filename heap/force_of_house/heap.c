/* Heap exploitation develop example. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#define HEAMNUM 16
char *heap_list[HEAMNUM];

void init_proc(){
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
}

void get_shell(){
    system("/bin/sh");
}

void menu(){
    puts("----------------------");
    puts("      Heap Baby       ");
    puts("----------------------");
    puts(" 1. Add a heap        ");
    puts(" 2. View a heap       ");
    puts(" 3. Delete a page     ");
    puts(" 4. Edit a page       ");
    puts(" 5. Exit              ");
    puts("----------------------");
    printf("Your choice :");
}

int readn(char *buf, int n){
    int len = read(0, buf, n);
    if(buf[len - 1] == '\n') buf[len - 1] = '\x00';
    return len;
}

int read_int(){
    char buf[16];
    readn(buf, 15);
    return atoi(buf);
}

void add(){
    int i;
    unsigned int size;
    char buf[16];
    char *ptr, *target = NULL;
    for(i = 0; ; i++){
        if(i >= HEAMNUM) {puts("Full"); return;}
        if(!heap_list[i]) break;
    }
    printf("Size :");
    size = read_int();
    ptr = (char *)malloc(size);
    if(!ptr){puts("Malloc Error"); exit(0);}
    heap_list[i] = ptr;
    printf("Content :");
    readn(ptr, size);
    printf("Create heap @ %#x\n", ptr);
}

void del(){
    unsigned int idx;
    char buf[16];
    printf("Index :");
    idx = read_int();
    if(idx >= HEAMNUM || !heap_list[idx]) {puts("Invalid index"); return;}
    free(heap_list[idx]);
    // heap_list[idx] = NULL;
}

void edit(){
    unsigned int idx, size;
    char buf[16];
    printf("Index :");
    idx = read_int();
    if(idx >= HEAMNUM || !heap_list[idx]) {puts("Invalid index"); return;}
    printf("Size :");
    size = read_int();
    printf("Content :");
    readn(heap_list[idx], size);
}

void view(){
    unsigned int idx;
    char buf[16];
    printf("Index :");
    idx = read_int();
    if(idx >= HEAMNUM || !heap_list[idx]) {puts("Invalid index"); return;}
    printf("Content :\n%s\n", heap_list[idx]);
}

int main() {
    int choice;
    init_proc();
    while(1){
        menu();
        choice = read_int();
        switch(choice){
            case 1: add(); break;
            case 2: view(); break;
            case 3: del(); break;
            case 4: edit(); break;
            case 5: exit(0); break;
            default: puts("Invalid choice");
        }
    }
    return 0;
}