#include "headers.h"
__global__ void hello_kernel()
{
    printf("Hello Kernel!\n");
}

void launch_kernel()
{
    hello_kernel <<<1,1>>> ();
}