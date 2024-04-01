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
    {"elements", 'e', "size", 0, "Number of elements to create for the mempool."},
    {"burst", 'b', "size", 0, "Number of packets per burst."},
    {"comm", 'c', "size", 0, "Number of bursts per communication list."},
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
    struct rte_mempool *mpool_payload;
    struct rte_pktmbuf_extmem ext_mem;
    struct rte_eth_stats stats;
    struct arguments args = {
        .ascii_percentage = 45,
        .ascii_runlen = 15,
        .kernel = VANILLA_CAPPING_THREAD,
        .queues = 1,
        .elements = 81920,
        .bsize = 1024,
        .rsize = 1024,
        .output = NULL};
    std::vector<GpuHostNicShmem *> shmem;
    uint16_t nb_rxd = 1024U, nb_txd = 1024U;
    uint8_t socket_id;
    int ret, id, tmp, queues, time_elapsed;

    cudaProfilerStop();
    signal(SIGINT, sighandler);

    /* =======================   Argument Parsing   ======================= */

    if ((ret = rte_eal_init(argc, argv)) < 0)
        fail("Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;
    
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

    ext_mem.elt_size = RTE_PKTBUF_DATAROOM + RTE_PKTMBUF_HEADROOM;                // packet size
    ext_mem.buf_len = RTE_ALIGN_CEIL(args.elements * ext_mem.elt_size, GPU_PAGE); // buffer size

    GpuHostNicShmem::shmem_register(&(ext_mem), &(dev_info), GPU_ID);
    mpool_payload = rte_pktmbuf_pool_create_extbuf("payload_mpool", args.elements,
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

    for (id = 0, tmp = 0; id < args.queues; id++)
    {
        tmp = rte_get_next_lcore(tmp, 1, 0);
        rte_eal_remote_launch(dx_core, (void *)(shmem[id]), tmp);

        tmp = rte_get_next_lcore(tmp, 1, 0);
        rte_eal_remote_launch(rx_core, (void *)(shmem[id]), tmp);
    }

    queues = shmem.size();
    time_elapsed = 0;

    sleep(5);
    while (GpuHostNicShmem::force_quit == false)
    {
        rte_eth_stats_get(NIC_PORT, &stats);
        time_elapsed += 5;

        puts("\n---------------------------------------------------------------------");
        printf("\nTime elapsed: %dh,%dm,%ds\n",
               time_elapsed / 3600,
               time_elapsed / 60 % 60,
               time_elapsed % 60);
        puts("DPDK queue information");
        for (id = 0; id < queues; id++)
            printf("Queue %d: %lu bytes, %lu packets received, %lu packets dropped\n",
                   id,
                   stats.q_ibytes[id],
                   stats.q_ipackets[id],
                   stats.q_errors[id]);
        puts("\nGpuHostNic queue information");
        for (auto &it : shmem)
        {
            it->logn.lock();
            it->logs.lock();
            printf("Queue %d: %.2f pps, %.2f bps (total), %.2f bps (stored)\n",
                   it->id,
                   (float)(it->stats.packets) / time_elapsed,
                   (float)(it->stats.total_bytes * 8) / time_elapsed,
                   (float)(it->stats.stored_bytes * 8) / time_elapsed);
            it->logs.unlock();
            it->logn.unlock();
        }
        sleep(5);
    }

    RTE_WAIT_WORKERS(id, ret);
    rte_eth_stats_get(NIC_PORT, &stats);

    puts("\n---------------------------------------------------------------------");
    puts("Exiting program...");
    puts("DPDK queue information");
    for (id = 0; id < queues; id++)
        printf("Queue %d: %lu bytes, %lu packets received, %lu packets dropped\n",
               id,
               stats.q_ibytes[id],
               stats.q_ipackets[id],
               stats.q_errors[id]);
    puts("\nGpuHostNic queue information");
    for (auto &it : shmem)
        printf("Queue %d: %lu packets, %lu bytes (total), %lu bytes (stored)\n",
               it->id,
               it->stats.packets,
               it->stats.total_bytes,
               it->stats.stored_bytes);


    /* =======================       Cleaning       ======================= */

    GpuHostNicShmem::shmem_unregister(&(ext_mem), &(dev_info), GPU_ID, NIC_PORT);
    shmem.clear();

    return EXIT_SUCCESS;
}