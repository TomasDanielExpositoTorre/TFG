#include "headers.h"

/* ========================================================================= */
/* =======================        ARGP CONFIG        ======================= */
/* ========================================================================= */
GpuHostNicShmem *shmem;
volatile bool GpuHostNicShmem::force_quit = false;

const char *argp_program_version = "Gpu HostNic 1.0";
const char *argp_program_bug_address = "<tomas.exposito@estudiante.uam.es>";

static struct argp_option options[] = {
    {"percentage", 'p', "value", 0, "Value for ascii percentage detection scheme."},
    {"runlen", 'r', "size", 0, "Value for ascii run detection scheme."},
    {"kernel", 'k', "type", 0, "Kernel used to process packets."},
    {"output", 'o', "filename", 0, "File where captured packets will be dumped."},
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
    shmem->self_quit = true;
    GpuHostNicShmem::force_quit = true;
}

/* ========================================================================= */
/* =======================            MAIN           ======================= */
/* ========================================================================= */


int main(int argc, char **argv)
{
    int ret = 0, id = 0;
    struct rte_eth_dev_info dev_info;
    struct rte_gpu_info gpu_info;
    struct arguments args;
    uint16_t nb_rxd = 1024U, nb_txd = 1024U;
    uint8_t socket_id;

    cudaProfilerStop();
    signal(SIGINT, sighandler);

    /* =======================   Argument Parsing   ======================= */

    RTE_CHECK((ret = rte_eal_init(argc, argv)) < 0, "Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;
    
    args.ascii_runlen = 15;
    args.ascii_percentage = 45;
    args.kernel = VANILLA_CAPPING_THREAD;
    args.output = NULL;
    argp_parse(&argp, argc, argv, 0, 0, &args);
    
    if (args.output == NULL)
    {
        fprintf(stderr, "Please provide a path to save captured packets to\n");
        return EXIT_FAILURE;
    }

    /* =======================     Device Setup     ======================= */

    cudaSetDevice(GPU_ID);
    cudaFree(0);
    shmem = new GpuHostNicShmem(args);

    /* Trust the user to send -a NIC-ADDR -a GPU-ADDR */
    RTE_CHECK(rte_eth_dev_count_avail() == 0, "No Ethernet ports found\n");
    RTE_CHECK(rte_gpu_count_avail() == 0, "No GPUs found\n");
    RTE_CHECK(rte_eth_dev_info_get(NIC_PORT, &dev_info), "Failed to get device info for port 0\n");
    RTE_CHECK(rte_gpu_info_get(GPU_ID, &gpu_info), "Failed to get gpu info\n");

    /* =======================  Mempool Allocation  ======================= */

    ext_mem.elt_size = RTE_PKTBUF_DATAROOM + RTE_PKTMBUF_HEADROOM;        // packet size
    ext_mem.buf_len = RTE_ALIGN_CEIL(ELEMS * ext_mem.elt_size, GPU_PAGE); // buffer size

    GpuHostNicShmem::shmem_register(&(ext_mem), &(dev_info), GPU_ID);
    mpool_payload = rte_pktmbuf_pool_create_extbuf("payload_mpool", ELEMS,
                                                   0, 0, ext_mem.elt_size,
                                                   rte_socket_id(), &ext_mem, 1);
    RTE_CHECK(mpool_payload == NULL, "Could not create EXT memory mempool\n");

    /* =======================     Port 0 Setup     ======================= */

    RTE_ERRCHECK(rte_eth_dev_configure(NIC_PORT, RXQUEUES, 0, &conf_eth_port),
            "Cannot configure device: err=%d, port=0\n", ret);
    RTE_ERRCHECK(rte_eth_dev_adjust_nb_rx_tx_desc(NIC_PORT, &nb_rxd, &nb_txd),
            "Cannot adjust number of descriptors: err=%d, port=0\n", ret);
    rte_eth_macaddr_get(NIC_PORT, &conf_ports_eth_addr[NIC_PORT]);

    /* =======================     RXQueue Setup    ======================= */

    socket_id = (uint8_t)rte_lcore_to_socket_id(0);

    RTE_ERRCHECK(rte_eth_rx_queue_setup(NIC_PORT, 0, nb_rxd, socket_id, NULL, mpool_payload),
        "rte_eth_rx_queue_setup: err=%d, port=0\n", ret);


    /* =======================    Device Startup    ======================= */
    RTE_ERRCHECK(rte_eth_dev_start(NIC_PORT),
        "rte_eth_dev_start: err=%d, port=0\n", ret);
    rte_eth_promiscuous_enable(NIC_PORT);

    /* =======================         Main         ======================= */
    id = rte_get_next_lcore(id, 1, 0);
    rte_eal_remote_launch(dx_core, (void *)(shmem), id);

    id = rte_get_next_lcore(id, 1, 0);
    rte_eal_remote_launch(rx_core, (void *)(shmem), id);

    RTE_WAIT_WORKERS(id, ret);

    /* =======================       Cleaning       ======================= */

    GpuHostNicShmem::shmem_unregister(&(ext_mem), &(dev_info), GPU_ID, NIC_PORT);

    return EXIT_SUCCESS;
}