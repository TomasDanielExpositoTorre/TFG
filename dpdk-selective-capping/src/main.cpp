#include "headers.h"

/* ========================================================================= */
/* =======================        ARGP CONFIG        ======================= */
/* ========================================================================= */
volatile bool CommunicationRing::force_quit = false;

const char *argp_program_version = "DPDK Selective Capping 1.0";
const char *argp_program_bug_address = "<tomas.exposito@estudiante.uam.es>";

static struct argp_option options[] = {
    {"percentage", 'p', "value", 0, "Value for ascii percentage detection scheme."},
    {"runlen", 'r', "size", 0, "Value for ascii run detection scheme."},
    {"kernel", 'k', "type", 0, "Kernel used to process packets."},
    {"output", 'o', "filename", 0, "File where captured packets will be dumped."},
    {"queues", 'q', "n", 0, "Number of queues to use for burst capture."},
    {"burst", 'b', "size", 0, "Number of packets per burst."},
    {"ringsize", 's', "size", 0, "Number of bursts per communication ring_vector."},
    {"workload", 'w', "type", 0, "0 for CPU, 1 for GPU"},
    {"threads", 't', "N", 0, "Threads for subring processing on CPU, bursts to process simultaneously on GPU"},
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
    .rx_adv_conf = {
        .rss_conf = {.rss_key = NULL, .rss_hf = RTE_ETH_RSS_IP},
    }};

/* ========================================================================= */
/* =======================            MAIN           ======================= */
/* ========================================================================= */

void sighandler(int signal)
{
    printf("\nSIGNAL received, stopping packet capture...\n");
    CommunicationRing::force_quit = true;
}

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
    std::vector<CommunicationRing *> ring_vector;
    uint16_t nb_rxd = 1024U, nb_txd = 1024U;
    int ret, id, tmp;

    cudaProfilerStop();
    signal(SIGINT, sighandler);

    /* =======================   Argument Parsing   ======================= */

    if ((ret = rte_eal_init(argc, argv)) < 0)
        fail("Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    argp_parse(&argp, argc, argv, 0, 0, &args);
    check_args(args);

#ifndef SIM_STORAGE
    fwrite_unlocked(&file_header, sizeof(pcap_file_header), 1, args.output);
#endif
    /* =======================     Device Setup     ======================= */

    cudaSetDevice(gpu);
    cudaFree(0);

    if (rte_eth_dev_count_avail() == 0)
        fail("No Ethernet ports found\n");
    if (args.gpu_workload && rte_gpu_count_avail() == 0)
        fail("No GPUs found\n");

    try(rte_eth_dev_info_get(port, &dev_info))
        fail("Cannot get ethdevice info: err=%d, port=0\n", ret);
    try(rte_gpu_info_get(gpu, &gpu_info))
        fail("Cannot get device info: err=%d, port=0\n", ret);

    /* =======================  Mempool Allocation  ======================= */

    ext_mem.elt_size = RTE_PKTBUF_DATAROOM + RTE_PKTMBUF_HEADROOM;                                   /* Metadata + Packet Size */
    ext_mem.buf_len = RTE_ALIGN_CEIL(args.ring_size * args.burst_size * ext_mem.elt_size, GPU_PAGE); /* Buffer Size */

    CommunicationRing::shmem_register(&(ext_mem), &(dev_info), args.gpu_workload);
    mpool_payload = rte_pktmbuf_pool_create_extbuf("payload_mpool", args.ring_size * args.burst_size,
                                                   0, 0, ext_mem.elt_size,
                                                   rte_socket_id(), &ext_mem, 1);
    if (mpool_payload == NULL)
        fail("Could not create EXT memory mempool\n");

    /* =======================     Port 0 Setup     ======================= */

    try(rte_eth_dev_configure(port, args.queues, 0, &conf_eth_port))
        fail("Cannot configure device: err=%d, port=0\n", ret);
    try(rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd))
        fail("Cannot adjust number of descriptors: err=%d, port=0\n", ret);

    /* =======================     RXQueue Setup    ======================= */

    for (id = 0; id < args.queues; id++)
        try(rte_eth_rx_queue_setup(port, id, nb_rxd, (uint8_t)rte_lcore_to_socket_id(id), NULL, mpool_payload))
            fail("rte_eth_rx_queue_setup: %s\n", rte_strerror(ret));

    /* =======================    Device Startup    ======================= */
    try(rte_eth_dev_start(port))
        fail("rte_eth_dev_start: err=%d, port=0\n", ret);
    rte_eth_promiscuous_enable(port);

    /* =======================         Main         ======================= */

    ring_vector.reserve(args.queues);

    if (args.gpu_workload)
        for (id = 0, tmp = 0; id < args.queues; id++)
        {
            ring_vector.push_back(new GpuCommunicationRing(args, id));

            tmp = rte_get_next_lcore(tmp, 1, 0);
            rte_eal_remote_launch(gpu_dx, (void *)(ring_vector[id]), tmp);

            tmp = rte_get_next_lcore(tmp, 1, 0);
            rte_eal_remote_launch(gpu_rx, (void *)(ring_vector[id]), tmp);
        }
    else if (args.threads == 1)
    {
        for (id = 0, tmp = 0; id < args.queues; id++)
        {
            ring_vector.push_back(new CpuCommunicationRing(args, id));

            tmp = rte_get_next_lcore(tmp, 1, 0);
            if (args.kernel == OPTIMIZED_CAPPING)
                rte_eal_remote_launch(cpu_opx, (void *)(ring_vector[id]), tmp);
            else
                rte_eal_remote_launch(cpu_px, (void *)(ring_vector[id]), tmp);

            tmp = rte_get_next_lcore(tmp, 1, 0);
            rte_eal_remote_launch(cpu_rx, (void *)(ring_vector[id]), tmp);
        }
        tmp = rte_get_next_lcore(tmp, 1, 0);

        if (args.queues == 1)
            rte_eal_remote_launch(cpu_dx, (void *)(ring_vector[0]), tmp);
        else
            rte_eal_remote_launch(cpu_ndx, static_cast<void *>(&ring_vector), tmp);
    }
    else
        for (id = 0, tmp = 0; id < args.queues; id++)
        {
            ring_vector.push_back(new SpuCommunicationRing(args, id, args.threads));

            tmp = rte_get_next_lcore(tmp, 1, 0);
            rte_eal_remote_launch(spu_dx, (void *)(ring_vector[id]), tmp); /* No support for single-core DX yet */

            if (args.kernel == OPTIMIZED_CAPPING)
                for (int j = 0; j < args.threads; j++)
                {
                    tmp = rte_get_next_lcore(tmp, 1, 0);
                    rte_eal_remote_launch(spu_opx, (void *)(ring_vector[id]), tmp);
                }
            else
                for (int j = 0; j < args.threads; j++)
                {
                    tmp = rte_get_next_lcore(tmp, 1, 0);
                    rte_eal_remote_launch(spu_px, (void *)(ring_vector[id]), tmp);
                }

            tmp = rte_get_next_lcore(tmp, 1, 0);
            rte_eal_remote_launch(spu_rx, (void *)(ring_vector[id]), tmp);
        }

    mastercore(ring_vector, args);

    /* =======================       Cleaning       ======================= */

    CommunicationRing::shmem_unregister(&(ext_mem), &(dev_info), port, args.gpu_workload);
    ring_vector.clear();

    return EXIT_SUCCESS;
}