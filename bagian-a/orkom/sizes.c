#include <stdio.h>

union sybau {
    char h;
    struct hawk* i;
    struct tuah* j;
};

struct hawk {
    union sybau a;
    int c;
    char b[3];
};

struct tuah {
    char d;
    int e[4];
    struct hawk* f;
    struct tuah* g;
};

int main(){
   printf("%d\n", sizeof(struct hawk));
   printf("%d\n", sizeof(struct tuah));
   printf("%d\n", sizeof(union sybau)); 
   return 0;
}
