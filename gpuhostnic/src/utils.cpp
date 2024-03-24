#include "headers.h"
#include <mutex>

error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *args = (struct arguments *)state->input;

    switch (key)
    {
    case 'p':
        args->ascii_percentage = atoi(arg);
        if (args->ascii_percentage <= 0 || args->ascii_percentage > 100)
        {
            fprintf(stderr, "Incorrect ASCII percentage. Value must be from 1 to 100\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'r':
        args->ascii_runlen = atoi(arg);
        if (args->ascii_runlen <= 0 || args->ascii_runlen > RTE_ETHER_MAX_LEN)
        {
            fprintf(stderr, "Incorrect ASCII runlen. Value must be a postive number\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'k':
        args->kernel = atoi(arg);
        if (args->kernel < VANILLA_CAPPING_THREAD || args->kernel > COERCIVE_CAPPING_WARP)
        {
            fprintf(stderr, "Incorrect kernel type. Value must be from %d to %d\n", VANILLA_CAPPING_THREAD, COERCIVE_CAPPING_WARP);
            exit(EXIT_FAILURE);
        }
        break;
    case 'o':
        if ((args->output = fopen(arg, "wb")) == NULL)
        {
            perror("fopen");
            exit(EXIT_FAILURE);
        }
        break;
    case 'q':
        args->queues = atoi(arg);
        if (args->queues <= 0)
        {
            fprintf(stderr, "Number of queues cannot be 0.\n");
            exit(EXIT_FAILURE);
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

int dx_core(void *args)
{
    GpuHostNicShmem *shm = (GpuHostNicShmem *)args;
    struct rte_gpu_comm_list *comm_list;
    struct pcap_packet_header packet_header;
    struct timeval ts;
    int ret = 0;
    bool cap;

    printf("[DX] Starting Core %d...\n", shm->id);
    cudaSetDevice(GPU_ID);

    while (keep_alive(shm))
    {
        while (keep_alive(shm) && shm->dxlist_isreadable(&ret) == false)
            if (ret != 0)
            {
                fprintf(stderr, "[DX] rte_gpu_comm_get_status error: %s", rte_strerror(ret));
                GpuHostNicShmem::force_quit = true;
                return EXIT_FAILURE;
            }

        if (killed(shm) && shm->dxlist_isreadable(&ret) == false)
            break;

        comm_list = shm->dxlist_read();

        for (uint32_t i = 0; i < comm_list->num_pkts; i++)
        {
            cap = comm_list->pkt_list[i].size & 1;
            comm_list->pkt_list[i].size >>= 1;
            gettimeofday(&(ts), NULL);
            packet_header.ts_sec = ts.tv_sec;
            packet_header.ts_usec = ts.tv_usec;
            packet_header.caplen = cap ? MAX_HLEN : comm_list->pkt_list[i].size;
            packet_header.len = comm_list->pkt_list[i].size;

            GpuHostNicShmem::write.lock();
            fwrite_unlocked(&(packet_header), sizeof(pcap_packet_header), 1, shm->pcap_fp);
            fwrite_unlocked((const void *)comm_list->pkt_list[i].addr, packet_header.caplen, 1, shm->pcap_fp);
            GpuHostNicShmem::write.unlock();
        }

        shm->dxlist_clean();
    }
    return EXIT_SUCCESS;
}

int rx_core(void *args)
{
    GpuHostNicShmem *shm = (GpuHostNicShmem *)args;
    struct rte_mbuf *packets[1024];
    int i, ret;

    printf("[RX] Starting Core %d...\n", shm->id);
    cudaSetDevice(GPU_ID);

    while (keep_alive(shm))
    {
        i = 0;

        while (shm->rxlist_iswritable(&ret) == false)
            if (ret != 0)
            {
                fprintf(stderr, "rte_gpu_comm_get_status error: %s", rte_strerror(ret));
                GpuHostNicShmem::force_quit = true;
                return EXIT_FAILURE;
            }

        /* Populate burst */
        while (keep_alive(shm) && i < (1024 - 8))
            i += rte_eth_rx_burst(NIC_PORT, shm->id, &(packets[i]), (1024 - i));

        if (i == 0)
            break;

        if (shm->rxlist_write(packets, i) != 0)
        {
            fprintf(stderr, "rte_gpu_comm_populate_list_pkts error: %s", rte_strerror(ret));
            GpuHostNicShmem::force_quit = true;
            return EXIT_FAILURE;
        }
        shm->rxlist_process(ceil(i, 32), 32);
    }
    return EXIT_SUCCESS;
}