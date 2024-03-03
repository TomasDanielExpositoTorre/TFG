#ifndef SPC_CUDA_H
#define SPC_CUDA_H

#include <cuda.h>
#include <cuda_runtime.h>
#include <cuda_runtime_api.h>
#include <cuda_profiler_api.h>

typedef enum __kernel__
{
    VANILLA_PACKET_THREAD = 0,   /* Each thread processes one packet with the vanilla algorithm      */
    OPTIMIZED_PACKET_THREAD = 1, /* Each thread processes one packet with the optimized algorithm    */
    NAIVE_PACKET_WARP = 2,       /* Each warp processes one packet by equally dividing the payload   */
    INVASIVE_PACKET_WARP = 3,    /* Naive implementation with an extra RUN-1 bytes per thread        */
    COERCIVE_PACKET_WARP = 4     /* Naive implementation with warp shared memory                     */
} kernel;

typedef struct __pipeline__
{
    unsigned short percentage;
    unsigned short runlen;
    unsigned short kernel;
} pipeline;

void launch_kernel();
#endif