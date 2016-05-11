#include <stdint.h>
#include <stdlib.h>

uint32_t dotprod(uint32_t *x, uint32_t *y, uint32_t size) {
    uint32_t res = 0;
    for(size_t i = 0; i < size; i++) {
        res += x[i] * y[i];
    }
    return res;
}
