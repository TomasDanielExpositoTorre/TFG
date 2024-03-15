#ifndef SPC_GCPUNIC_H
#define SPC_GCPUNIC_H
#include "headers.h"

#define has_quit(shm) shm->self_quit || shm->force_quit
#define not_quit(shm) !shm->self_quit && !shm->force_quit

class GpuHostNicShmem
{
private:
    struct rte_gpu_comm_list *comm_list;
    int rxi, dxi;
    int size;

public:
    struct kernel_args args;
    cudaStream_t stream;
    volatile bool self_quit;
    static volatile bool force_quit;

    GpuHostNicShmem(struct kernel_args _args);
    ~GpuHostNicShmem();

    static void shmem_register(struct rte_pktmbuf_extmem *ext_mem,
                               struct rte_eth_dev_info *dev_info,
                               int gpu_id);
    static void shmem_unregister(struct rte_pktmbuf_extmem *ext_mem,
                                 struct rte_eth_dev_info *dev_info,
                                 int gpu_id, int port_id);
    bool list_iswritable();
    bool list_isreadable(int *ret);
    bool list_push(rte_mbuf **packets, int mbufsize);
    void list_process(int blocks, int threads);
    void list_pop();
};
#endif