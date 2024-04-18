#include "headers.h"

CommunicationRing::CommunicationRing(struct arguments args, int i)
{
    pcap_fp = args.output;
    ring_size = args.ring_size;
    burst_size = args.burst_size;
    this->args = args;
    id = i;

    self_quit = false;
    stats = {
        .packets = 0,
        .total_bytes = 0,
        .stored_bytes = 0,
    };

    headers = (struct pcap_packet_header *)malloc(ring_size * burst_size * sizeof(headers[0]));
    if (headers == NULL)
    {
        fprintf(stderr, "Failed to create memory for burst packet headers\n");
        exit(EXIT_FAILURE);
    }
}

void CommunicationRing::shmem_register(struct rte_pktmbuf_extmem *ext_mem,
                                       struct rte_eth_dev_info *dev_info,
                                       bool using_gpu)
{
    ext_mem->buf_ptr = rte_malloc("extmem", ext_mem->buf_len, 0);

    if (ext_mem->buf_ptr == NULL)
        rte_exit(EXIT_FAILURE, "Could not allocate CPU DPDK memory\n");

    if (using_gpu && rte_gpu_mem_register(GPU_ID, ext_mem->buf_len, ext_mem->buf_ptr) < 0)
        rte_exit(EXIT_FAILURE, "Unable to gpudev register addr 0x%p\n", ext_mem->buf_ptr);

    if (rte_dev_dma_map(dev_info->device, ext_mem->buf_ptr, ext_mem->buf_iova, ext_mem->buf_len))
        rte_exit(EXIT_FAILURE, "Could not DMA map EXT memory\n");
}

void CommunicationRing::shmem_unregister(struct rte_pktmbuf_extmem *ext_mem,
                                         struct rte_eth_dev_info *dev_info,
                                         int port_id, bool using_gpu)
{
    int ret = 0;
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    if (rte_dev_dma_unmap(dev_info->device, ext_mem->buf_ptr, ext_mem->buf_iova, ext_mem->buf_len))
        rte_exit(EXIT_FAILURE, "Could not DMA unmap EXT memory\n");
    if (using_gpu && (ret = rte_gpu_mem_unregister(GPU_ID, ext_mem->buf_ptr)) < 0)
        rte_exit(EXIT_FAILURE, "rte_gpu_mem_unregister returned error %d\n", ret);
}
