#include "headers.h"

GpuHostNicShmem::GpuHostNicShmem(struct arguments args, int i)
{
    cudaError_t ret;

    kargs.ascii_percentage = args.ascii_percentage;
    kargs.ascii_runlen = args.ascii_runlen;
    kargs.kernel = args.kernel;
    pcap_fp = args.output;
    id = i;

    rxi = dxi = 0;
    size = 1024U;
    stats.packets = 0;
    stats.stored_bytes = 0;
    stats.total_bytes = 0;
    
    burst_headers = (struct pcap_packet_header *)malloc(size * sizeof(burst_headers[0]));
    if (burst_headers == NULL)
    {
        fprintf(stderr, "Failed to create memory for burst packet headers\n");
        exit(EXIT_FAILURE);
    }

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
    rte_gpu_comm_destroy_list(comm_list, size);
}

/* ==========================  Static  Functions  ========================== */

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

/* ==========================  DxCore  Functions  ========================== */

bool GpuHostNicShmem::dxlist_isreadable(int *err)
{
    enum rte_gpu_comm_list_status s;
    *err = rte_gpu_comm_get_status(&comm_list[dxi], &s);
    return s == RTE_GPU_COMM_LIST_DONE;
}

struct rte_gpu_comm_list *GpuHostNicShmem::dxlist_read(struct pcap_packet_header* burst_header)
{
    *burst_header = burst_headers[dxi];
    return &(comm_list[dxi]);
}

void GpuHostNicShmem::dxlist_clean()
{
    rte_gpu_comm_cleanup_list(&(comm_list[dxi]));
    dxi = (dxi + 1) % size;
}

/* ==========================  RxCore  Functions  ========================== */

bool GpuHostNicShmem::rxlist_iswritable(int *err)
{
    enum rte_gpu_comm_list_status s;
    *err = rte_gpu_comm_get_status(&comm_list[rxi], &s);
    return s == RTE_GPU_COMM_LIST_FREE;
}

int GpuHostNicShmem::rxlist_write(rte_mbuf **packets, int mbufsize)
{
    struct timeval ts;
    gettimeofday(&(ts), NULL);
    burst_headers[rxi].ts_sec = ts.tv_sec;
    burst_headers[rxi].ts_usec = ts.tv_usec;
    return rte_gpu_comm_populate_list_pkts(&(comm_list[rxi]), packets, mbufsize);
}

void GpuHostNicShmem::rxlist_process(int blocks, int threads)
{
    launch_kernel(&(comm_list[rxi]), blocks, threads, stream, kargs);
    rxi = (rxi + 1) % size;
}