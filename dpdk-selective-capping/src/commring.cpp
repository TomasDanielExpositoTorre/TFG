#include "headers.h"

CommunicationRing::CommunicationRing(struct arguments args, int i)
{
    pcap_fp = args.output;
    ring_size = args.ring_size;
    burst_size = args.burst_size;
    this->args = args;
    id = i;

    self_quit = false;
    rxi = dxi = 0;
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

/* ==========================  STATIC  FUNCTIONS  ========================== */

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

/* ========================================================================= */
/* =======================  GPU COMMUNICATION RING   ======================= */
/* ========================================================================= */

GpuCommunicationRing::GpuCommunicationRing(struct arguments args, int i) : CommunicationRing(args, i)
{
    cudaError_t ret;

    if ((comm_list = rte_gpu_comm_create_list(GPU_ID, ring_size)) == NULL)
        rte_panic("rte_gpu_comm_create_list");

    if ((ret = cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking)) != cudaSuccess)
    {
        fprintf(stderr, "Cuda failed with %s \n", cudaGetErrorString(ret));
        exit(EXIT_FAILURE);
    }

    if (rte_gpu_mem_register(GPU_ID, burst_size * ring_size * sizeof(headers[0]), headers) < 0)
        rte_exit(EXIT_FAILURE, "Unable to gpudev register packet headers");
}

GpuCommunicationRing::~GpuCommunicationRing()
{
    cudaStreamDestroy(stream);
    rte_gpu_comm_destroy_list(comm_list, ring_size);
    rte_gpu_mem_unregister(GPU_ID, headers);
    free(headers);
}

/* ==========================  RXLIST  FUNCTIONS  ========================== */

bool GpuCommunicationRing::rxlist_iswritable()
{
    enum rte_gpu_comm_list_status s;
    int ret = rte_gpu_comm_get_status(&comm_list[rxi], &s);
    if (ret != 0)
    {
        GpuCommunicationRing::force_quit = true;
        fail("[R-Core %d] rte_gpu_comm_get_status error: %s\n", id, rte_strerror(ret));
    }

    return s == RTE_GPU_COMM_LIST_FREE;
}

int GpuCommunicationRing::rxlist_write()
{
    int i = 0;
    while (CommunicationRing::force_quit == false && i < (burst_size - RTE_RXBURST_ALIGNSIZE))
        i += rte_eth_rx_burst(NIC_PORT, id, &(burst[i]), (burst_size - i));

#ifdef PCAP_NANOSECONDS
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    headers[rxi * burst_size].ts_sec = ts.tv_sec;
    headers[rxi * burst_size].ts_nsec = ts.tv_nsec;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    headers[rxi * burst_size].ts_sec = tv.tv_sec;
    headers[rxi * burst_size].ts_nsec = tv.tv_usec;
#endif

    rxlog.lock();
    stats.packets += i;
    for (int j = 0; j < i; j++)
        stats.total_bytes += burst[j]->data_len;
    rxlog.unlock();

    return i;
}

void GpuCommunicationRing::rxlist_process(int npackets)
{
    int ret = rte_gpu_comm_populate_list_pkts(&(comm_list[rxi]), burst, npackets);

    if (ret != 0)
    {
        GpuCommunicationRing::force_quit = true;
        fail("[R-Core %d] rte_gpu_comm_get_status error: %s\n", id, rte_strerror(ret));
    }

    launch_kernel(&(comm_list[rxi]), 1, burst_size, stream, args, (headers + rxi * burst_size));
    rxi = (rxi + 1) % ring_size;
}

/* ==========================  DXLIST  FUNCTIONS  ========================== */

bool GpuCommunicationRing::dxlist_isempty()
{
    enum rte_gpu_comm_list_status s;
    rte_gpu_comm_get_status(&comm_list[dxi], &s);
    return s == RTE_GPU_COMM_LIST_FREE;
}

bool GpuCommunicationRing::dxlist_isreadable()
{
    enum rte_gpu_comm_list_status s;
    int ret = rte_gpu_comm_get_status(&comm_list[dxi], &s);
    if (ret != 0)
    {
        GpuCommunicationRing::force_quit = true;
        fail("[R-Core %d] rte_gpu_comm_get_status error: %s\n", id, rte_strerror(ret));
    }
    return s == RTE_GPU_COMM_LIST_DONE;
}

struct rte_mbuf **GpuCommunicationRing::dxlist_read(struct pcap_packet_header **pkt_headers, int *num_pkts)
{
    *(pkt_headers) = headers + burst_size * dxi;
    *num_pkts = comm_list[dxi].num_pkts;

    return comm_list[dxi].mbufs;
}

void GpuCommunicationRing::dxlist_clean()
{
    rte_pktmbuf_free_bulk((&(comm_list[dxi]))->mbufs, (&(comm_list[dxi]))->num_pkts);
    rte_gpu_comm_cleanup_list(&(comm_list[dxi]));
    dxi = (dxi + 1) % ring_size;
}

/* ========================================================================= */
/* =======================  CPU COMMUNICATION RING   ======================= */
/* ========================================================================= */

CpuCommunicationRing::CpuCommunicationRing(struct arguments args, int i) : CommunicationRing(args, i)
{
    pxi = 0;

    nbpackets = (int *)malloc(ring_size * sizeof(nbpackets[0]));
    burstate = (int *)calloc(ring_size, sizeof(burstate[0]));
    packet_ring = (struct rte_mbuf ***)malloc(ring_size * sizeof(packet_ring[0]));

    if (nbpackets == NULL || burstate == NULL || packet_ring == NULL)
    {
        fprintf(stderr, "Failed to create memory for cpu packet ring\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < ring_size; i++)
    {
        packet_ring[i] = (struct rte_mbuf **)malloc(burst_size * sizeof(packet_ring[i][0]));
        if (packet_ring[i] == NULL)
        {
            for (int j = i - 1; j >= 0; j--)
                free(packet_ring[j]);
            free(packet_ring);
            free(nbpackets);
            free(burstate);
            fprintf(stderr, "Failed to create memory for cpu packet ring\n");
            exit(EXIT_FAILURE);
        }
    }
}
CpuCommunicationRing::~CpuCommunicationRing()
{
    for (int i = 0; i < ring_size; i++)
        free(packet_ring[i]);
    free(packet_ring);
    free(nbpackets);
    free(burstate);
    free(headers);
}

/* ==========================  RXLIST  FUNCTIONS  ========================== */

bool CpuCommunicationRing::rxlist_iswritable()
{
    return burstate[rxi] == BURST_FREE;
}

int CpuCommunicationRing::rxlist_write()
{
    int i = 0;

    while (CommunicationRing::force_quit == false && i < (burst_size - RTE_RXBURST_ALIGNSIZE))
        i += rte_eth_rx_burst(NIC_PORT, id, &(packet_ring[rxi][i]), (burst_size - i));

#ifdef PCAP_NANOSECONDS
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    headers[rxi * burst_size].ts_sec = ts.tv_sec;
    headers[rxi * burst_size].ts_nsec = ts.tv_nsec;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    headers[rxi * burst_size].ts_sec = tv.tv_sec;
    headers[rxi * burst_size].ts_nsec = tv.tv_usec;
#endif

    rxlog.lock();
    stats.packets += i;

    for (int j = 0; j < i; j++)
        stats.total_bytes += packet_ring[rxi][j]->data_len;
    rxlog.unlock();

    return i;
}

void CpuCommunicationRing::rxlist_process(int npackets)
{
    nbpackets[rxi] = npackets;
    burstate[rxi] = BURST_PROCESSING;
    rxi = (rxi + 1) % ring_size;
}

/* ==========================  PXLIST  FUNCTIONS  ========================== */

bool CpuCommunicationRing::pxlist_isempty()
{
    return burstate[pxi] == BURST_FREE;
}

bool CpuCommunicationRing::pxlist_isready()
{
    return burstate[pxi] == BURST_PROCESSING;
}

struct rte_mbuf **CpuCommunicationRing::pxlist_read(int *num_pkts, struct pcap_packet_header **pkt_headers)
{
    *num_pkts = nbpackets[pxi];
    *(pkt_headers) = headers + pxi * burst_size;
    return packet_ring[pxi];
}

void CpuCommunicationRing::pxlist_done()
{
    burstate[pxi] = BURST_DONE;
    pxi = (pxi + 1) % ring_size;
}

/* ==========================  DXLIST  FUNCTIONS  ========================== */

bool CpuCommunicationRing::dxlist_isempty()
{
    return burstate[dxi] == BURST_FREE;
}

bool CpuCommunicationRing::dxlist_isreadable()
{
    return burstate[dxi] == BURST_DONE;
}

struct rte_mbuf **CpuCommunicationRing::dxlist_read(struct pcap_packet_header **pkt_headers, int *num_pkts)
{
    *(pkt_headers) = headers + burst_size * dxi;
    *num_pkts = nbpackets[dxi];
    return packet_ring[dxi];
}

void CpuCommunicationRing::dxlist_clean()
{
    rte_pktmbuf_free_bulk(packet_ring[dxi], nbpackets[dxi]);
    burstate[dxi] = BURST_FREE;
    dxi = (dxi + 1) % ring_size;
}
