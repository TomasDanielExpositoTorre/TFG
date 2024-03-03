#include "headers.h"

/* ========================================================================= */
/* =======================        ARGP CONFIG        ======================= */
/* ========================================================================= */

const char *argp_program_version = "Gpu HostNic 1.0";
const char *argp_program_bug_address = "<tomas.exposito@estudiante.uam.es>";

static struct argp_option options[] = {
    {"percentage", 'p', "value", 0, "Interface used to capture packets."},
    {"runlen", 'r', "size", 0, "Interface used to capture packets."},
    {"kernel", 'k', "type", 0, "Interface used to capture packets."},
    {0}};

static struct argp argp = {options, parse_opt, 0, NULL};

/* ========================================================================= */
/* =======================        DPDK CONFIG        ======================= */
/* ========================================================================= */

struct rte_ether_addr conf_ports_eth_addr[RTE_MAX_ETHPORTS];
struct rte_mempool *mpool_payload, *mpool_header;
struct rte_pktmbuf_extmem ext_mem;

static struct rte_eth_conf conf_eth_port = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_RSS,
        .offloads = RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT, // Required by buffer split feature
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
        .offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS,
    },
    .rx_adv_conf = {
        .rss_conf = {.rss_key = NULL, .rss_hf = RTE_ETH_RSS_IP},
    }};

/* ========================================================================= */
/* =======================        SIG HANDLER        ======================= */
/* ========================================================================= */

void sighandler(int signal)
{
    printf("\nSIGNAL received, stopping packet capture...\n");
    // @todo: tell other cores/gpu to stop
}

/* ========================================================================= */
/* =======================            MAIN           ======================= */
/* ========================================================================= */

int main(int argc, char **argv)
{
    int eal_args, tmp = 0;
    struct rte_eth_dev_info dev_info;
    struct rte_gpu_info gpu_info;
    kernel_args args;
    uint16_t nb_rxd = 1024U, nb_txd = 1024U;
    uint8_t socket_id;
    cudaProfilerStop();
    signal(SIGINT, sighandler);

    /* ======================= EAL Argument Parsing ======================= */
    if ((eal_args = rte_eal_init(argc, argv)) < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    argc -= eal_args;
    argv += eal_args;

    /* ======================= SPC Argument Parsing ======================= */
    KARGS_INIT((&args));
    argp_parse(&argp, argc, argv, 0, 0, &args);

    /* =======================     Device Setup     ======================= */
    cudaSetDevice(GPU_ID);
    cudaFree(0);

    /* Trust the user to send -a NIC-ADDR -a GPU-ADDR */
    TRY(rte_eth_dev_count_avail() == 0,
        "No Ethernet ports found\n");
    TRY(rte_eth_dev_info_get(NIC_PORT, &dev_info),
        "Failed to get device info for port 0\n");
    printf("\nDevice driver name in use: %s... \n", dev_info.driver_name);

    TRY(rte_gpu_count_avail() == 0,
        "No Ethernet ports found\n");
    TRY(rte_gpu_info_get(GPU_ID, &gpu_info),
        "Failed to get gpu info\n");
    printf("\tGPU ID %d\n\t\tparent ID %d GPU Bus ID %s NUMA node %d Tot memory %.02f MB, Tot processors %d\n",
           gpu_info.dev_id,
           gpu_info.parent,
           gpu_info.name,
           gpu_info.numa_node,
           (((float)gpu_info.total_memory) / (float)1024) / (float)1024,
           gpu_info.processor_count);

    /* =======================  Mempool Allocation  ======================= */

    /* For now, alloc buffer on CPU and share to GPU */
    ext_mem.elt_size = RTE_PKTBUF_DATAROOM + RTE_PKTMBUF_HEADROOM;        // packet size
    ext_mem.buf_len = RTE_ALIGN_CEIL(ELEMS * ext_mem.elt_size, GPU_PAGE); // buffer size

    TRY((ext_mem.buf_ptr = rte_malloc("extmem", ext_mem.buf_len, 0)) == NULL,
        "Could not allocate CPU DPDK memory\n");
    VTRY(rte_gpu_mem_register(0, ext_mem.buf_len, ext_mem.buf_ptr) < 0,
         "Unable to gpudev register addr 0x%p\n", ext_mem.buf_ptr);
    TRY(rte_dev_dma_map(dev_info.device, ext_mem.buf_ptr, ext_mem.buf_iova, ext_mem.buf_len),
        "Could not DMA map EXT memory\n");

    mpool_payload = rte_pktmbuf_pool_create_extbuf("payload_mpool", ELEMS,
                                                   0, 0, ext_mem.elt_size,
                                                   rte_socket_id(), &ext_mem, 1);
    TRY(mpool_payload == NULL,
        "Could not create EXT memory mempool\n");

    /* =======================     Port 0 Setup     ======================= */
    TRY(rte_eth_dev_configure(NIC_PORT, RXQUEUES, TXQUEUES, &conf_eth_port),
        "Cannot configure device on port 0\n");
    TRY(rte_eth_dev_adjust_nb_rx_tx_desc(NIC_PORT, &nb_rxd, &nb_txd) < 0,
        "Cannot adjust number of descriptors on port 0\n");
    rte_eth_macaddr_get(NIC_PORT, &conf_ports_eth_addr[NIC_PORT]);

    /* =======================     RX/TX Queues     ======================= */
    socket_id = (uint8_t)rte_lcore_to_socket_id(0);

    TRY(rte_eth_rx_queue_setup(NIC_PORT, 0, nb_rxd, socket_id, NULL, mpool_payload),
        "rte_eth_rx_queue_setup error\n");

    TRY(rte_eth_tx_queue_setup(NIC_PORT, 0, nb_txd, socket_id, NULL),
        "rte_eth_tx_queue_setup error\n");

    /* =======================    Device Startup    ======================= */
    TRY(rte_eth_dev_start(NIC_PORT), "rte_eth_dev_start error\n");
    rte_eth_promiscuous_enable(NIC_PORT);
    printf("Port %d, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
           NIC_PORT,
           conf_ports_eth_addr[NIC_PORT].addr_bytes[0],
           conf_ports_eth_addr[NIC_PORT].addr_bytes[1],
           conf_ports_eth_addr[NIC_PORT].addr_bytes[2],
           conf_ports_eth_addr[NIC_PORT].addr_bytes[3],
           conf_ports_eth_addr[NIC_PORT].addr_bytes[4],
           conf_ports_eth_addr[NIC_PORT].addr_bytes[5]);

    /* =======================      Main (real_)     ======================= */
    tmp = rte_get_next_lcore(tmp, 1, 0);
    rte_eal_remote_launch(tx_core, (void *)0, tmp);

    tmp = rte_get_next_lcore(tmp, 1, 0);
    rte_eal_remote_launch(rx_core, (void *)0, tmp);

    int icore = 0;
    RTE_LCORE_FOREACH_WORKER(icore)
    {
        if (rte_eal_wait_lcore(icore) < 0)
        {
            fprintf(stderr, "bad exit for coreid: %d\n", icore);
            break;
        }
    }
    /* =======================       Cleaning       ======================= */
    rte_eth_dev_stop(NIC_PORT);
    rte_eth_dev_close(NIC_PORT);
    TRY(rte_dev_dma_unmap(dev_info.device, ext_mem.buf_ptr, ext_mem.buf_iova, ext_mem.buf_len),
        "Could not DMA unmap EXT memory\n");
    TRY(rte_gpu_mem_unregister(0, ext_mem.buf_ptr) < 0,
        "rte_gpu_mem_unregister returned error.\n");

    return EXIT_SUCCESS;
}