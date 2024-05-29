#include "headers.h"

error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *args = (struct arguments *)state->input;
    switch (key)
    {
    case 'p':
        args->ascii_percentage = atoi(arg);
        if (args->ascii_percentage <= 0 || args->ascii_percentage > 100)
            fail("Incorrect ASCII percentage. Value must be from 1 to 100.\n");
        break;
    case 'r':
        args->ascii_runlen = atoi(arg);
        if (args->ascii_runlen <= 0 || args->ascii_runlen > (RTE_ETHER_MAX_LEN - MIN_HLEN))
            fail("Incorrect ASCII runlen. Value must be a valid number for ethernet packets.\n");
        break;
    case 'o':
#ifndef SIM_STORAGE
        if ((args->output = fopen(arg, "wb")) == NULL)
        {
            perror("fopen");
            exit(EXIT_FAILURE);
        }
#endif
        break;
    case 'q':
        args->queues = atoi(arg);
        if (args->queues <= 0)
            fail("Number of queues cannot be 0.\n");
        break;
    case 'c':
        args->ring_size = atoi(arg);
        if (args->ring_size <= 0)
            fail("Number of bursts for communication list must be greater than 0.\n");
        break;
    case 'b':
        args->burst_size = atoi(arg);
        if (args->burst_size <= 0)
            fail("Burst size must be greater than 0.\n");
        break;
    case 't':
        args->threads = atoi(arg);
        if (args->threads == 0)
            fail("Given threads must be more than 0.\n");
        break;
    case 'w':
        args->gpu_workload = atoi(arg) % 2;
        break;
    case 'k':
        args->kernel = atoi(arg) % 2;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

void check_args(struct arguments args)
{
    int min_cores = args.gpu_workload     ? args.queues * 2 + 1
                    : (args.threads == 1) ? args.queues * 3 + 1
                                          : args.queues * (args.threads + 2) + 1;

    if (args.gpu_workload && args.burst_size > 1024)
        fail("Invalid burst size for GPU workload: %d\n", args.burst_size);

    if (min_cores > (int)rte_lcore_count())
        fail("Number of cores should be at least %d to support %d queues for this workload.\n", min_cores, args.queues);

    if (args.queues > 8)
        fail("Up to 8 queues are supported for this implementation\n");
}

void mastercore(std::vector<CommunicationRing *> &ring, struct arguments args)
{
    struct rte_eth_stats stats;
    int id, ret, time_elapsed = 0;
    float pps, sbps, tbps;
    char su, tu;

    sleep(5);
    while (CommunicationRing::force_quit == false)
    {
        rte_eth_stats_get(NIC_PORT, &stats);
        time_elapsed += 5;

        puts("\n---------------------------------------------------------------------");
        printf("\nTime elapsed: %02d:%02d:%02d\n",
               time_elapsed / 3600,
               time_elapsed / 60 % 60,
               time_elapsed % 60);
        puts("Capture ring information");
        for (id = 0; id < args.queues; id++)
            printf("Queue %d: %lu bytes, %lu packets received, %lu packets dropped\n",
                   id,
                   stats.q_ibytes[id],
                   stats.q_ipackets[id],
                   stats.q_errors[id]);

        puts("\nProcessing ring information");
        for (auto &it : ring)
        {
            it->rxlog.lock();
            it->dxlog.lock();
            pps = it->stats.packets;
            tbps = it->stats.total_bytes;
            sbps = it->stats.stored_bytes;
            it->dxlog.unlock();
            it->rxlog.unlock();

            pps /= time_elapsed;
            tbps = (tbps * 8) / time_elapsed;
            sbps = (sbps * 8) / time_elapsed;

            speed_format(tbps, tu);
            speed_format(sbps, su);

            printf("Queue %d: %.2f pps, %.2f %cbps (total), %.2f %cbps (stored)\n",
                   it->id, pps, tbps, tu, sbps, su);
        }
        sleep(5);
    }

    RTE_WAIT_WORKERS(id, ret);
    rte_eth_stats_get(NIC_PORT, &stats);

    puts("\n---------------------------------------------------------------------");
    puts("Exiting program...");
    puts("Capture ring information");
    for (id = 0; id < args.queues; id++)
        printf("Queue %d: %lu bytes, %lu packets received, %lu packets dropped\n",
               id,
               stats.q_ibytes[id],
               stats.q_ipackets[id],
               stats.q_errors[id]);
    puts("\nProcessing ring information");
    for (auto &it : ring)
    {
        tbps = it->stats.total_bytes * 8;
        sbps = it->stats.stored_bytes * 8;
        speed_format(tbps, tu);
        speed_format(sbps, su);

        printf("Queue %d: %lu packets, %.2f %cb (total), %.2f %cb (stored)\n",
               it->id, it->stats.packets, tbps, tu, sbps, su);
    }
}