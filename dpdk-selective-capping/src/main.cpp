#include "headers.h"

/* ========================================================================= */
/* =======================        ARGP CONFIG        ======================= */
/* ========================================================================= */
volatile bool CommunicationRing::force_quit = false;
std::mutex CommunicationRing::write;

const char *argp_program_version = "DPDK Selective Capping 1.0";
const char *argp_program_bug_address = "<tomas.exposito@estudiante.uam.es>";

static struct argp_option options[] = {
    {"percentage", 'p', "value", 0, "Value for ascii percentage detection scheme."},
    {"runlen", 'r', "size", 0, "Value for ascii run detection scheme."},
    {"kernel", 'k', "type", 0, "Kernel used to process packets."},
    {"output", 'o', "filename", 0, "File where captured packets will be dumped."},
    {"queues", 'q', "n", 0, "Number of queues to use for burst capture."},
    {"burst", 'b', "size", 0, "Number of packets per burst."},
    {"comm", 'c', "size", 0, "Number of bursts per communication ring."},
    {"workload", 'w', "type", 0, "0 for CPU, 1 for GPU"},
    {"threads", 't', "N", 0, "Threads for subring processing on CPU"},
    {0}};

static struct argp argp = {options, parse_opt, 0, NULL};

/* ========================================================================= */
/* =======================        DPDK CONFIG        ======================= */
/* ========================================================================= */

static struct rte_eth_conf conf_eth_port = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_RSS,
        .offloads = RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT, // Required by buffer split feature
    },
    // .txmode = {
    //     .mq_mode = RTE_ETH_MQ_TX_NONE,
    //     .offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS,
    // },
    .rx_adv_conf = {
        .rss_conf = {.rss_key = NULL, .rss_hf = RTE_ETH_RSS_IP},
    }};

/* ========================================================================= */
/* =======================        SIG HANDLER        ======================= */
/* ========================================================================= */

void sighandler(int signal)
{
    printf("\nSIGNAL received, stopping packet capture...\n");
    CommunicationRing::force_quit = true;
}

/* ========================================================================= */
/* =======================            MAIN           ======================= */
/* ========================================================================= */

int main(int argc, char **argv)
{
    struct pcap_file_header file_header;
    struct rte_eth_dev_info dev_info;
    struct rte_gpu_info gpu_info;
    struct rte_mempool *mpool_payload;
    struct rte_pktmbuf_extmem ext_mem;
    struct arguments args = {
        .ascii_percentage = 45,
        .ascii_runlen = 15,
        .kernel = SELECTIVE_CAPPING,
        .queues = 1,
        .threads = 1,
        .burst_size = 1024,
        .ring_size = 1024,
        .gpu_workload = false,
        .output = NULL,
    };
    std::vector<CommunicationRing *> shmem;
    uint16_t nb_rxd = 1024U, nb_txd = 1024U;
    uint8_t socket_id;
    int ret, id, tmp, min_cores;

    cudaProfilerStop();
    signal(SIGINT, sighandler);

    /* =======================   Argument Parsing   ======================= */

    if ((ret = rte_eal_init(argc, argv)) < 0)
        fail("Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    argp_parse(&argp, argc, argv, 0, 0, &args);

    min_cores = args.gpu_workload ? 2 * args.queues + 1 : 3 * args.queues + 1;
    if (min_cores > (int)rte_lcore_count())
        fail("Number of cores should be at least %d to suppport %d queues for this workload.\n", min_cores, args.queues);

    fwrite_unlocked(&file_header, sizeof(pcap_file_header), 1, args.output);

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

    ext_mem.elt_size = RTE_PKTBUF_DATAROOM + RTE_PKTMBUF_HEADROOM;                                   // packet size
    ext_mem.buf_len = RTE_ALIGN_CEIL(args.ring_size * args.burst_size * ext_mem.elt_size, GPU_PAGE); // buffer size

    CommunicationRing::shmem_register(&(ext_mem), &(dev_info), args.gpu_workload);
    mpool_payload = rte_pktmbuf_pool_create_extbuf("payload_mpool", args.ring_size * args.burst_size,
                                                   0, 0, ext_mem.elt_size,
                                                   rte_socket_id(), &ext_mem, 1);
    if (mpool_payload == NULL)
        fail("Could not create EXT memory mempool\n");

    /* =======================     Port 0 Setup     ======================= */

    try(rte_eth_dev_configure(NIC_PORT, args.queues, 0, &conf_eth_port))
        fail("Cannot configure device: err=%d, port=0\n", ret);
    try(rte_eth_dev_adjust_nb_rx_tx_desc(NIC_PORT, &nb_rxd, &nb_txd))
        fail("Cannot adjust number of descriptors: err=%d, port=0\n", ret);

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

    shmem.reserve(args.queues);

    if (args.gpu_workload)
        for (id = 0, tmp = 0; id < args.queues; id++)
        {
            shmem.push_back(new GpuCommunicationRing(args, id));

            tmp = rte_get_next_lcore(tmp, 1, 0);
            rte_eal_remote_launch(dxcore, (void *)(shmem[id]), tmp);

            tmp = rte_get_next_lcore(tmp, 1, 0);
            rte_eal_remote_launch(rxcore, (void *)(shmem[id]), tmp);
        }
    else if (args.threads == 1)
        for (id = 0, tmp = 0; id < args.queues; id++)
        {
            shmem.push_back(new CpuCommunicationRing(args, id));

            tmp = rte_get_next_lcore(tmp, 1, 0);
            rte_eal_remote_launch(dxcore, (void *)(shmem[id]), tmp);

            tmp = rte_get_next_lcore(tmp, 1, 0);
            if (args.kernel == OPTIMIZED_CAPPING)
                rte_eal_remote_launch(pxcore, (void *)(shmem[id]), tmp);
            else
                rte_eal_remote_launch(opxcore, (void *)(shmem[id]), tmp);

            tmp = rte_get_next_lcore(tmp, 1, 0);
            rte_eal_remote_launch(rxcore, (void *)(shmem[id]), tmp);
        }
    else
        for (id = 0, tmp = 0; id < args.queues; id++)
        {
            shmem.push_back(new SpuCommunicationRing(args, id, args.threads));

            tmp = rte_get_next_lcore(tmp, 1, 0);
            rte_eal_remote_launch(sdxcore, (void *)(shmem[id]), tmp);

            if (args.kernel == OPTIMIZED_CAPPING)
                for (int j = 0; j < args.threads; j++)
                {
                    tmp = rte_get_next_lcore(tmp, 1, 0);
                    rte_eal_remote_launch(sopxcore, (void *)(shmem[id]), tmp);
                }
            else
                for (int j = 0; j < args.threads; j++)
                {
                    tmp = rte_get_next_lcore(tmp, 1, 0);
                    rte_eal_remote_launch(spxcore, (void *)(shmem[id]), tmp);
                }

            tmp = rte_get_next_lcore(tmp, 1, 0);
            rte_eal_remote_launch(srxcore, (void *)(shmem[id]), tmp);
        }

    mastercore(shmem, args);

    /* =======================       Cleaning       ======================= */

    CommunicationRing::shmem_unregister(&(ext_mem), &(dev_info), NIC_PORT, args.gpu_workload);
    shmem.clear();

    return EXIT_SUCCESS;
}