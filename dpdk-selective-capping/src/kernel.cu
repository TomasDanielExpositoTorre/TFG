#include "headers.h"

__global__ void selective_capping(struct rte_gpu_comm_list *global_list,
                                  struct pcap_packet_header *headers,
                                  struct arguments args)
{
    int id = threadIdx.x;
    int block = blockIdx.x;
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    struct rte_gpu_comm_list *comm_list = &(global_list[block]);
    int runlen = 0, total = 0;
    int psize;
    char *packet;

    if (id < comm_list->num_pkts)
    {
        packet = (char *)(comm_list->pkt_list[id].addr);
        psize = comm_list->pkt_list[id].size;

        /* Broadcast capture time through burst*/
        headers[i].ts_sec = headers[i].ts_sec;
        headers[i].ts_usec = headers[i].ts_usec;
        headers[i].len = psize;

        for (int j = MIN_HLEN; j < psize; j++)
        {
            if (packet[j] >= MIN_ASCII && packet[j] <= MAX_ASCII)
            {
                runlen++;
                total += 100;
                if (runlen == args.ascii_runlen)
                    j = psize;
            }
            else
                runlen = 0;
        }

        if (MAX_HLEN > psize || runlen == args.ascii_runlen || total >= (args.ascii_percentage * (psize - MIN_HLEN)))
            headers[i].caplen = psize;
        else
            headers[i].caplen = MAX_HLEN;
    }

    __syncthreads();

    if (id == 0)
        *(comm_list->status_d) = RTE_GPU_COMM_LIST_DONE;
}

__global__ void optimized_capping(struct rte_gpu_comm_list *global_list,
                                  struct pcap_packet_header *headers,
                                  struct arguments args)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    struct rte_gpu_comm_list *comm_list = &(global_list[blockIdx.x]);
    int runlen = 0, total = 0, seen = 0;
    int psize;
    char *packet;

    if (threadIdx.x < comm_list->num_pkts)
    {
        packet = (char *)(comm_list->pkt_list[threadIdx.x].addr);
        psize = comm_list->pkt_list[threadIdx.x].size;

        /* Broadcast capture time through burst*/
        headers[i].ts_sec = headers[i].ts_sec;
        headers[i].ts_usec = headers[i].ts_usec;
        headers[i].len = psize;

        for (int j = MIN_HLEN + args.ascii_runlen - 1; j >= MIN_HLEN && j < psize; j--, seen++)
        {
            if (packet[j] >= MIN_ASCII && packet[j] <= MAX_ASCII)
            {
                runlen++;
                total += 100;
                if (runlen == args.ascii_runlen)
                    j = psize;
            }
            else
            {
                runlen = 0;
                j += args.ascii_runlen + 1;
            }
        }

        if (MAX_HLEN > psize || runlen == args.ascii_runlen || total >= (args.ascii_percentage * seen))
            headers[i].caplen = psize;
        else
            headers[i].caplen = MAX_HLEN;
    }

    __syncthreads();

    if (threadIdx.x == 0)
        *(comm_list->status_d) = RTE_GPU_COMM_LIST_DONE;
}

void launch_kernel(struct rte_gpu_comm_list *comm_list, int blocks, int threads,
                   cudaStream_t stream, struct arguments args,
                   struct pcap_packet_header *headers)
{
    if (args.kernel == SELECTIVE_CAPPING)
        selective_capping<<<blocks, threads, 0, stream>>>(comm_list, headers, args);
    else
        optimized_capping<<<blocks, threads, 0, stream>>>(comm_list, headers, args);
}