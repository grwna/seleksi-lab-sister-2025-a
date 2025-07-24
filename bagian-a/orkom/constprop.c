#include <math.h>

double test_constant() {
    int r = 10;
    return sin(0.67 * r - 6); 
}

double test_variable(double x) {
    return sin(x); 
}

int main() {
    test_constant();
    test_variable(1.57); 
    return 0;
}
