#ifndef SPC_GCPUNIC_H
#define SPC_GCPUNIC_H
#include "headers.h"

#define killed(shm) (shm->force_quit || shm->self_quit)
#define keep_alive(shm) (!shm->force_quit && !shm->self_quit)

class GpuHostNicShmem
{
private:
    struct rte_gpu_comm_list *comm_list;
    int rxi, dxi;
    int size;

public:
    struct kernel_arguments kargs;
    cudaStream_t stream;
    volatile bool self_quit;
    static volatile bool force_quit;
    FILE *pcap_fp;

    GpuHostNicShmem(struct arguments args);
    ~GpuHostNicShmem();

    static void shmem_register(struct rte_pktmbuf_extmem *ext_mem,
                               struct rte_eth_dev_info *dev_info,
                               int gpu_id);
    static void shmem_unregister(struct rte_pktmbuf_extmem *ext_mem,
                                 struct rte_eth_dev_info *dev_info,
                                 int gpu_id, int port_id);

    bool dxlist_isreadable(int *ret);
    struct rte_gpu_comm_list *dxlist_read();
    void dxlist_clean();

    bool rxlist_iswritable(int *ret);
    int rxlist_write(struct rte_mbuf **packets, int mbufsize);
    void rxlist_process(int blocks, int threads);
};
#endif