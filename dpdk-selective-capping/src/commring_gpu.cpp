#include "headers.h"

GpuCommunicationRing::GpuCommunicationRing(struct arguments args, int i) : CommunicationRing(args, i)
{
    cudaError_t ret;

    rxi = dxi = pxi = 0;
    qbursts = 0;
    mbursts = args.threads;

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
    headers[rxi * burst_size].ts_usec = ts.tv_nsec;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    headers[rxi * burst_size].ts_sec = tv.tv_sec;
    headers[rxi * burst_size].ts_usec = tv.tv_usec;
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
    // launch_kernel(comm_list + rxi, 1, burst_size, stream, args, (headers + rxi * burst_size));

    qbursts = (qbursts + 1) % mbursts;

    if (qbursts == 0)
    {
        launch_kernel(comm_list + pxi, mbursts, burst_size, stream, args, (headers + pxi * burst_size));
        pxi = (pxi + mbursts) % ring_size;
    }
    else if (SpuCommunicationRing::force_quit == true)
    {
        launch_kernel(comm_list + pxi, qbursts, burst_size, stream, args, (headers + pxi * burst_size));
        pxi = (pxi + qbursts) % ring_size;
    }
    rxi = (rxi + 1) % ring_size;
}

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