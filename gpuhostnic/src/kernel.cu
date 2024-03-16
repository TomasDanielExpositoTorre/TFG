#include "headers.h"

__global__ void vanilla_capping_thread(struct rte_gpu_comm_list *comm_list, struct kernel_arguments args)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    int runlen = 0, total = 0;
    int packetlen;
    char *packet;

    if (i < comm_list->num_pkts)
    {
        packet = (char *)(comm_list->pkt_list[i].addr);
        packetlen = comm_list->pkt_list[i].size;
        comm_list->pkt_list[i].size <<= 1;

        for (int j = MIN_HLEN; j < packetlen; j++)
        {
            if (packet[j] >= MIN_ASCII && packet[j] <= MAX_ASCII)
            {
                runlen++;
                total += 100;
                if (runlen == args.ascii_runlen)
                    return; /* Don't cap */
            }
            else
                runlen = 0;
        }

        if (total >= (args.ascii_percentage * packetlen))
            return; /* Don't cap */

        comm_list->pkt_list[i].size |= 1; /* Cap to MAX_HLEN bytes */
    }

    __threadfence();
    __syncthreads();

    if (i == 0)
    {
        *(comm_list->status_d) = RTE_GPU_COMM_LIST_DONE;
        __threadfence_system();
    }
    __syncthreads();
}

__global__ void optimized_capping_thread(struct rte_gpu_comm_list *comm_list, struct kernel_arguments args)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    int runlen = 0, total = 0, seen = 0;
    int packetlen;
    char *packet;

    if (i < comm_list->num_pkts)
    {
        packet = (char *)(comm_list->pkt_list[i].addr);
        packetlen = comm_list->pkt_list[i].size;
        comm_list->pkt_list[i].size <<= 1;

        /* Don't cap if payload is less than runlen */
        if (MIN_HLEN + args.ascii_runlen > comm_list->pkt_list[i].size)
            return;

        for (int j = MIN_HLEN + args.ascii_runlen - 1; j >= MIN_HLEN && j < packetlen; j--, seen++)
        {
            if (packet[j] >= MIN_ASCII && packet[j] <= MAX_ASCII)
            {
                runlen++;
                total += 100;
                if (runlen == args.ascii_runlen)
                    return; /* Do not cap */
            }
            else
            {
                runlen = 0;
                j += args.ascii_runlen + 1;
            }
        }

        if (total >= (args.ascii_percentage * seen))
            return; /* Do not cap */

        comm_list->pkt_list[i].size |= 1; /* Cap to MAX_HLEN bytes */
    }

    __threadfence();
    __syncthreads();

    if (i == 0)
    {
        *(comm_list->status_d) = RTE_GPU_COMM_LIST_DONE;
        __threadfence_system();
    }
    __syncthreads();
}

__global__ void naive_capping_warp(struct rte_gpu_comm_list *comm_list, struct kernel_arguments args)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    printf("%d\n", i);
}

__global__ void invasive_capping_warp(struct rte_gpu_comm_list *comm_list, struct kernel_arguments args)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    printf("%d\n", i);
}

__global__ void coercive_capping_warp(struct rte_gpu_comm_list *comm_list, struct kernel_arguments args)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    printf("%d\n", i);
}

void launch_kernel(struct rte_gpu_comm_list *comm_list, int blocks, int threads, cudaStream_t stream, struct kernel_arguments args)
{
    if (args.kernel == VANILLA_CAPPING_THREAD)
        vanilla_capping_thread<<<blocks, threads, 0, stream>>>(comm_list, args);
    else if (args.kernel == OPTIMIZED_CAPPING_THREAD)
        optimized_capping_thread<<<blocks, threads, 0, stream>>>(comm_list, args);
    else if (args.kernel == NAIVE_CAPPING_WARP)
        naive_capping_warp<<<blocks, threads, 0, stream>>>(comm_list, args);
    else if (args.kernel == INVASIVE_CAPPING_WARP)
        invasive_capping_warp<<<blocks, threads, 0, stream>>>(comm_list, args);
    else
        coercive_capping_warp<<<blocks, threads, 0, stream>>>(comm_list, args);
}