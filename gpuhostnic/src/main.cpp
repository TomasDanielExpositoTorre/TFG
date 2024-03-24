#include "headers.h"

/* ========================================================================= */
/* =======================        ARGP CONFIG        ======================= */
/* ========================================================================= */
volatile bool GpuHostNicShmem::force_quit = false;
std::mutex GpuHostNicShmem::write;
const char *argp_program_version = "Gpu HostNic 1.0";
const char *argp_program_bug_address = "<tomas.exposito@estudiante.uam.es>";

static struct argp_option options[] = {
    {"percentage", 'p', "value", 0, "Value for ascii percentage detection scheme."},
    {"runlen", 'r', "size", 0, "Value for ascii run detection scheme."},
    {"kernel", 'k', "type", 0, "Kernel used to process packets."},
    {"output", 'o', "filename", 0, "File where captured packets will be dumped."},
    {"queues", 'q', "n", 0, "Number of queues to use for burst capture."},
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
    GpuHostNicShmem::force_quit = true;
}

/* ========================================================================= */
/* =======================            MAIN           ======================= */
/* ========================================================================= */

int main(int argc, char **argv)
{
    struct pcap_file_header file_header;
    struct rte_eth_dev_info dev_info;
    struct rte_gpu_info gpu_info;
    struct arguments args;
    int ret, id, tmp;
    uint16_t nb_rxd = 1024U, nb_txd = 1024U;
    uint8_t socket_id;
    std::vector<GpuHostNicShmem *> shmem;

    cudaProfilerStop();
    signal(SIGINT, sighandler);

    /* =======================   Argument Parsing   ======================= */

    if ((ret = rte_eal_init(argc, argv)) < 0)
        fail("Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    args.ascii_runlen = 15;
    args.ascii_percentage = 45;
    args.kernel = VANILLA_CAPPING_THREAD;
    args.output = NULL;
    args.queues = 1;
    argp_parse(&argp, argc, argv, 0, 0, &args);

    fwrite_unlocked(&file_header, sizeof(pcap_file_header), 1, args.output);

    shmem.reserve(args.queues);
    for (int i = 0; i < args.queues; i++)
        shmem.push_back(new GpuHostNicShmem(args, i));

    /* =======================     Device Setup     ======================= */

    cudaSetDevice(GPU_ID);
    cudaFree(0);

    if (!rte_eth_dev_count_avail())
        fail("No Ethernet ports found\n");
    if (!rte_gpu_count_avail())
        fail("No GPUs found\n");

    try(rte_eth_dev_info_get(NIC_PORT, &dev_info))
        fail("Cannot get ethdevice info: err=%d, port=0\n", ret);
    try(rte_gpu_info_get(GPU_ID, &gpu_info))
        fail("Cannot get device info: err=%d, port=0\n", ret);

    /* =======================  Mempool Allocation  ======================= */

    ext_mem.elt_size = RTE_PKTBUF_DATAROOM + RTE_PKTMBUF_HEADROOM;        // packet size
    ext_mem.buf_len = RTE_ALIGN_CEIL(ELEMS * ext_mem.elt_size, GPU_PAGE); // buffer size

    GpuHostNicShmem::shmem_register(&(ext_mem), &(dev_info), GPU_ID);
    mpool_payload = rte_pktmbuf_pool_create_extbuf("payload_mpool", ELEMS,
                                                   0, 0, ext_mem.elt_size,
                                                   rte_socket_id(), &ext_mem, 1);
    if (mpool_payload == NULL)
        fail("Could not create EXT memory mempool\n");

    /* =======================     Port 0 Setup     ======================= */

    try(rte_eth_dev_configure(NIC_PORT, args.queues, 0, &conf_eth_port))
        fail("Cannot configure device: err=%d, port=0\n", ret);
    try(rte_eth_dev_adjust_nb_rx_tx_desc(NIC_PORT, &nb_rxd, &nb_txd))
        fail("Cannot adjust number of descriptors: err=%d, port=0\n", ret);
    rte_eth_macaddr_get(NIC_PORT, &conf_ports_eth_addr[NIC_PORT]);

    /* =======================     RXQueue Setup    ======================= */

    for (id = 0; id < args.queues; id++)
    {
        socket_id = (uint8_t)rte_lcore_to_socket_id(id);

        try(rte_eth_rx_queue_setup(NIC_PORT, id, nb_rxd, socket_id, NULL, mpool_payload))
            fail("rte_eth_rx_queue_setup: %s\n", rte_strerror(ret));
    }

    /* =======================    Device Startup    ======================= */
    try(rte_eth_dev_start(NIC_PORT))
        fail("rte_eth_dev_start: err=%d, port=0\n", ret);
    rte_eth_promiscuous_enable(NIC_PORT);

    /* =======================         Main         ======================= */

    for (id = 0, tmp = 0; id < args.queues; id++)
    {
        tmp = rte_get_next_lcore(tmp, 1, 0);
        rte_eal_remote_launch(dx_core, (void *)(shmem[id]), tmp);

        tmp = rte_get_next_lcore(tmp, 1, 0);
        rte_eal_remote_launch(rx_core, (void *)(shmem[id]), tmp);
    }

    RTE_WAIT_WORKERS(id, ret);

    /* =======================       Cleaning       ======================= */

    GpuHostNicShmem::shmem_unregister(&(ext_mem), &(dev_info), GPU_ID, NIC_PORT);
    shmem.clear();

    return EXIT_SUCCESS;
}