#include "headers.h"

__global__ void selective_capping(struct rte_gpu_comm_list *global_list,
                                  struct pcap_packet_header *headers,
                                  int ascii_runlen, int ascii_percentage)
{
    struct rte_gpu_comm_list *comm_list = &(global_list[blockIdx.x]);
    int i = blockIdx.x * blockDim.x + threadIdx.x, j;
    int runlen = 0, total = 0;
    int packetlen;
    char *packet;

    if (threadIdx.x < comm_list->num_pkts)
    {
        packet = (char *)(comm_list->pkt_list[threadIdx.x].addr);
        packetlen = comm_list->pkt_list[threadIdx.x].size;

        /* Broadcast capture time through burst */
        headers[i].ts_sec = headers[i].ts_sec;
        headers[i].ts_usec = headers[i].ts_usec;
        headers[i].len = packetlen;

        for (j = MIN_HLEN; j < packetlen; j++)
        {
            if (packet[j] >= MIN_ASCII && packet[j] <= MAX_ASCII)
            {
                runlen++;
                total += 100;
                if (runlen == ascii_runlen)
                    j = packetlen;
            }
            else
                runlen = 0;
        }

        if (MAX_HLEN > packetlen || runlen == ascii_runlen || total >= (ascii_percentage * (packetlen - MIN_HLEN)))
            headers[i].caplen = packetlen;
        else
            headers[i].caplen = MAX_HLEN;
    }

    __syncthreads();

    if (threadIdx.x == 0)
        *(comm_list->status_d) = RTE_GPU_COMM_LIST_DONE;
}

__global__ void optimized_capping(struct rte_gpu_comm_list *global_list,
                                  struct pcap_packet_header *headers,
                                  int ascii_runlen, int ascii_percentage)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x, j, k;
    struct rte_gpu_comm_list *comm_list = &(global_list[blockIdx.x]);
    int total = 0, seen = 0;
    int packetlen;
    char *packet;

    if (threadIdx.x < comm_list->num_pkts)
    {
        packet = (char *)(comm_list->pkt_list[threadIdx.x].addr);
        packetlen = comm_list->pkt_list[threadIdx.x].size;

        /* Broadcast capture time through burst*/
        headers[i].ts_sec = headers[i].ts_sec;
        headers[i].ts_usec = headers[i].ts_usec;
        headers[i].len = packetlen;

        for (j = MIN_HLEN + ascii_runlen - 1; j < packetlen; j += ascii_runlen)
        {
            seen++;
            if (packet[j] >= MIN_ASCII && packet[j] <= MAX_ASCII) /* Start of run found, iterate backwards*/
            {
                total += 100;
                for (k = j - 1; k > j - ascii_runlen; k--)
                {
                    seen++;
                    if (packet[k] >= MIN_ASCII && packet[k] <= MAX_ASCII)
                        total += 100;
                    else
                    {
                        j = k;
                        k = -1;
                    }
                }
                headers[i].caplen = packetlen; /* Run finished, do not cap */
                j = packetlen;
            }
        }
        if (MAX_HLEN > packetlen || total >= (ascii_percentage * seen))
            headers[i].caplen = packetlen;
        else
            headers[i].caplen = MAX_HLEN;
    }

    __syncthreads();

    if (threadIdx.x == 0)
        *(comm_list->status_d) = RTE_GPU_COMM_LIST_DONE;
}

void launch_kernel(struct rte_gpu_comm_list *comm_list, int blocks, int threads,
                   cudaStream_t stream, int ascii_runlen, int ascii_percentage, int kernel,
                   struct pcap_packet_header *headers)
{
    if (kernel == SELECTIVE_CAPPING)
        selective_capping<<<blocks, threads, 0, stream>>>(comm_list, headers, ascii_runlen, ascii_percentage);
    else
        optimized_capping<<<blocks, threads, 0, stream>>>(comm_list, headers, ascii_runlen, ascii_percentage);
}