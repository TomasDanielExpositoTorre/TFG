#include "headers.h"

CommunicationRing::CommunicationRing(struct arguments args, int i)
{
    pcap_fp = args.output;
    ring_size = args.ring_size;
    burst_size = args.burst_size;
    ascii_runlen = args.ascii_runlen;
    ascii_percentage = args.ascii_percentage;
    id = i;

    self_quit = false;
    stats = {
        .packets = 0,
        .total_bytes = 0,
        .stored_bytes = 0,
    };

    headers = new struct pcap_packet_header[ring_size * burst_size];
}

CommunicationRing::~CommunicationRing()
{
    delete[] headers;
}

void CommunicationRing::shmem_register(struct rte_pktmbuf_extmem *ext_mem,
                                       struct rte_eth_dev_info *dev_info,
                                       bool using_gpu)
{
    ext_mem->buf_ptr = rte_malloc("extmem", ext_mem->buf_len, 0);

    if (ext_mem->buf_ptr == NULL)
        fail("Could not allocate CPU DPDK memory\n");

    if (using_gpu && rte_gpu_mem_register(gpu, ext_mem->buf_len, ext_mem->buf_ptr) < 0)
        fail("Unable to gpudev register addr 0x%p\n", ext_mem->buf_ptr);

    if (rte_dev_dma_map(dev_info->device, ext_mem->buf_ptr, ext_mem->buf_iova, ext_mem->buf_len))
        fail("Could not DMA map EXT memory\n");
}

void CommunicationRing::shmem_unregister(struct rte_pktmbuf_extmem *ext_mem,
                                         struct rte_eth_dev_info *dev_info,
                                         int port_id, bool using_gpu)
{
    int ret = 0;
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);

    if (rte_dev_dma_unmap(dev_info->device, ext_mem->buf_ptr, ext_mem->buf_iova, ext_mem->buf_len))
        fail("Could not DMA unmap EXT memory\n");
    if (using_gpu && (ret = rte_gpu_mem_unregister(gpu, ext_mem->buf_ptr)) < 0)
        fail("rte_gpu_mem_unregister returned error %d\n", ret);
}

CpuCommunicationRing::CpuCommunicationRing(struct arguments args, int i) : CommunicationRing(args, i)
{
    rxi = pxi = dxi = 0;
    npkts = new int[ring_size];
    burst_state = new int[ring_size]();
    packet_ring = new struct rte_mbuf **[ring_size];

    for (int i = 0; i < ring_size; i++)
        packet_ring[i] = new struct rte_mbuf *[burst_size];
}

CpuCommunicationRing::~CpuCommunicationRing()
{
    for (int i = 0; i < ring_size; i++)
        delete[] packet_ring[i];
    delete[] packet_ring;
    delete[] burst_state;
    delete[] npkts;
}

SpuCommunicationRing::SpuCommunicationRing(struct arguments args, int i, int threads) : CommunicationRing(args, i)
{
    tids = 0;
    nthreads = threads;
    subring_size = ring_size / nthreads;

    rxi = new int[nthreads];
    dxi = new int[nthreads];
    pxi = new int[nthreads];
    sri = new int[nthreads];
    npkts = new int[ring_size];
    burst_state = new int[ring_size]();
    packet_ring = new struct rte_mbuf **[ring_size];

    for (int i = 0; i < ring_size; i++)
        packet_ring[i] = new struct rte_mbuf *[burst_size];

    for (int i = 0; i < nthreads; i++)
        rxi[i] = pxi[i] = dxi[i] = sri[i] = (subring_size * i);
}

SpuCommunicationRing::~SpuCommunicationRing()
{
    for (int i = 0; i < ring_size; i++)
        delete[] packet_ring[i];
    delete[] packet_ring;
    delete[] burst_state;
    delete[] npkts;
    delete[] rxi;
    delete[] pxi;
    delete[] dxi;
    delete[] sri;
}

int SpuCommunicationRing::gettid()
{
    int tid;
    tlock.lock();
    tid = tids++;
    tlock.unlock();
    return tid;
}

GpuCommunicationRing::GpuCommunicationRing(struct arguments args, int i) : CommunicationRing(args, i)
{
    assert((ring_size % args.threads) == 0);
    cudaError_t ret;

    current = 0;
    next = 0;
    rxi = dxi = pxi = 0;
    nsbr = args.threads;
    sbr_size = ring_size / nsbr;
    kernel = args.kernel;
    indices = new int[nsbr];

    for (int i = 0; i < nsbr; i++)
        indices[i] = (i+1) * sbr_size;

    if ((comm_list = rte_gpu_comm_create_list(gpu, ring_size)) == NULL)
        rte_panic("rte_gpu_comm_create_list");

    if ((ret = cudaStreamCreateWithFlags(&stream, cudaStreamNonBlocking)) != cudaSuccess)
        fail("Cuda failed with %s \n", cudaGetErrorString(ret));

    if (rte_gpu_mem_register(gpu, burst_size * ring_size * sizeof(headers[0]), headers) < 0)
        fail("Unable to gpudev register packet headers");
}

GpuCommunicationRing::~GpuCommunicationRing()
{
    cudaStreamDestroy(stream);
    rte_gpu_comm_destroy_list(comm_list, ring_size);
    rte_gpu_mem_unregister(gpu, headers);
}

void GpuCommunicationRing::rxlist_process(int npkts)
{
    int ret;
    if ((ret = rte_gpu_comm_populate_list_pkts(&(comm_list[rxi]), burst, npkts)) != 0)
    {
        GpuCommunicationRing::force_quit = true;
        fail("[R-Core %d] rte_gpu_comm_get_status error: %s\n", id, rte_strerror(ret));
    }

    if (rxi == (indices[next] - 1))
    {
        launch_kernel(comm_list + indices[next] - sbr_size, sbr_size, burst_size, stream,
                      ascii_runlen, ascii_percentage, kernel, (headers + (indices[next] - sbr_size) * burst_size));
        next = (next + 1) % nsbr;
    }
}