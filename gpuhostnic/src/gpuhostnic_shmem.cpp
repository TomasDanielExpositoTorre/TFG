#include "headers.h"

GpuHostNicShmem::GpuHostNicShmem(struct kernel_args _args)
{
    cudaError_t ret;
    args = _args;
    rxi = dxi = 0;
    quit = 0;
    size = 1024U;

    /* Esto hasta que no importe GDRCopy como que revienta */
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

bool GpuHostNicShmem::list_iswritable()
{
    enum rte_gpu_comm_list_status s;
    int ret = rte_gpu_comm_get_status(&comm_list[rxi], &s);
    return ret == 0 && s == RTE_GPU_COMM_LIST_FREE;
}

bool GpuHostNicShmem::list_isreadable(int *ret)
{
    enum rte_gpu_comm_list_status s;
    *ret = rte_gpu_comm_get_status(&comm_list[dxi], &s);
    return s == RTE_GPU_COMM_LIST_DONE;
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

void GpuHostNicShmem::list_pop()
{
    rte_gpu_comm_cleanup_list(&(comm_list[dxi]));
    dxi = (dxi + 1) % size;
}

void GpuHostNicShmem::shmem_register(struct rte_pktmbuf_extmem *ext_mem,
                                     struct rte_eth_dev_info *dev_info,
                                     int gpu_id)
{
    ext_mem->buf_ptr = rte_malloc("extmem", ext_mem->buf_len, 0);

    if (ext_mem->buf_ptr == NULL)
        rte_exit(EXIT_FAILURE, "Could not allocate CPU DPDK memory\n");
    if (rte_gpu_mem_register(gpu_id, ext_mem->buf_len, ext_mem->buf_ptr) < 0)
        rte_exit(EXIT_FAILURE, "Unable to gpudev register addr 0x%p\n", ext_mem->buf_ptr);
    if (rte_dev_dma_map(dev_info->device, ext_mem->buf_ptr, ext_mem->buf_iova, ext_mem->buf_len))
        rte_exit(EXIT_FAILURE, "Could not DMA map EXT memory\n");
}

void GpuHostNicShmem::shmem_unregister(struct rte_pktmbuf_extmem *ext_mem,
                                       struct rte_eth_dev_info *dev_info,
                                       int gpu_id, int port_id)
{
    int ret = 0;
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    if (rte_dev_dma_unmap(dev_info->device, ext_mem->buf_ptr, ext_mem->buf_iova, ext_mem->buf_len))
        rte_exit(EXIT_FAILURE, "Could not DMA unmap EXT memory\n");
    if ((ret = rte_gpu_mem_unregister(gpu_id, ext_mem->buf_ptr)) < 0)
        rte_exit(EXIT_FAILURE, "rte_gpu_mem_unregister returned error %d\n", ret);
}