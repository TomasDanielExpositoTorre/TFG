#include "headers.h"

GpuHostNicShmem::GpuHostNicShmem(struct kernel_args _args)
{
    cudaError_t ret;
    args = _args;
    rxi = wxi = 0;
    quit = 0;
    size = 1024U;
    
    if ((comm_list = rte_gpu_comm_create_list(GPU_ID, size)) == NULL)
        rte_panic("rte_gpu_comm_create_list");

    if ((ret = cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking)) != cudaSuccess)
    {
        fprintf(stderr, "Cuda failed with %s \n", cudaGetErrorString(ret));
        exit(EXIT_FAILURE);
    }
}

GpuHostNicShmem::~GpuHostNicShmem()
{
    cudaStreamDestroy(stream);
    rte_gpu_comm_destroy_list(comm_list, BURST_ELEMS);
}

bool GpuHostNicShmem::list_free()
{
    enum rte_gpu_comm_list_status s;
    int ret = rte_gpu_comm_get_status(&comm_list[rxi], &s);
    return ret == 0 && s == RTE_GPU_COMM_LIST_FREE;
}

bool GpuHostNicShmem::list_push(rte_mbuf **packets, int mbufsize)
{
    return rte_gpu_comm_populate_list_pkts(&(comm_list[rxi]), packets, mbufsize) == 0;
}

void GpuHostNicShmem::list_process(int blocks, int threads)
{
    launch_kernel(&(comm_list[rxi]), blocks, threads, stream, args);
    rxi = (rxi + 1) % size;
}