#ifndef SPC_GCPUNIC_H
#define SPC_GCPUNIC_H
#include "headers.h"
#include <mutex>

#define killed(shm) (shm->force_quit)

#define keep_alive(shm) (!shm->force_quit)

struct queue_stats
{
    unsigned long int packets;
    unsigned long int total_bytes;
    unsigned long int stored_bytes;
};

/**
 * Implementation of a shared memory wrapper between CPU, GPU and NIC.
 *
 * Communication between the CPU and GPU is done through a packet burst
 * ring, where:
 * - A CPU reception core populates packet bursts.
 * - A GPU kernel processes the populated packets.
 * - A CPU dumping core writes processed packets from this list in pcap format.
 */
class GpuHostNicShmem
{
private:
    struct rte_gpu_comm_list *comm_list;
    int rxi, dxi;
    int size;

public:
    static volatile bool force_quit;
    static std::mutex write;
    struct kernel_arguments kargs;
    struct queue_stats stats;
    struct pcap_packet_header *burst_headers;
    std::mutex logn, logs;
    cudaStream_t stream;
    FILE *pcap_fp;
    int id;
    int bsize;

    /**
     * Constructor method for this object. Creates the necessary elements
     * for CPU-GPU communication and attaches to a file for packet dumping.
     *
     * @param args: arguments to be sent to kernel, pcap output path.
     * @param i: Identifier for this object.
     */
    GpuHostNicShmem(struct arguments args, int i);
    ~GpuHostNicShmem();

    /**
     * Class method that allocates and maps CPU memory from ext_mem to
     * the given ethernet device and GPU.
     *
     * This method sets the virtual address of the ext_mem data buffer,
     * but expects initialized ele_size and buf_len values to be
     * initialized.
     *
     * @param ext_mem: An external buffer with defined element and total sizes.
     * @param dev_info: Ethernet device where the buffer will be mapped.
     * @param gpu_id: ID for the GPU where the buffer will be mapped.
     */
    static void shmem_register(struct rte_pktmbuf_extmem *ext_mem,
                               struct rte_eth_dev_info *dev_info,
                               int gpu_id);

    /**
     * Class method that closes a started ethernet device on the given port,
     * and unmaps CPU the memory address on ext_mem from the ethernet device
     * and GPU.
     *
     * @param ext_mem: External buffer data to unmap.
     * @param dev_info: Ethernet device mapped to the buffer.
     * @param gpu_id: ID from the GPU mapped to the buffer.
     */
    static void shmem_unregister(struct rte_pktmbuf_extmem *ext_mem,
                                 struct rte_eth_dev_info *dev_info,
                                 int gpu_id, int port_id);

    /**
     * Checks if the current packet burst is ready to be dumped to disk.
     * If a GPU communication error occurs, err is set to -rte_errno.
     *
     * @param err: Return from communication get status. Output Parameter.
     *
     * @returns True if the packet burst status is RTE_GPU_COMM_LIST_DONE,
     * False otherwise.
     */
    bool dxlist_isreadable(int *err);

    /**
     * Returns the processed packet burst from GPU.
     *
     * Values from this struct have been altered to inidicate whether the
     * packet should be capped to a predefined size, and should be re-modified
     * by the dumping core to prevent clashes with dpdk.
     *
     * Modifications to the original struct consist of a 1-bit left-shift in
     * the packet's size to store the aforementioned flag.
     */
    struct rte_gpu_comm_list *dxlist_read(struct pcap_packet_header *burst_header);

    /**
     * Restores the packet burst list to its original state and returns mbufs
     * to the mempool. This method also sets the packet burst list to
     * RTE_GPU_COMM_LIST_FREE, and moves to the next element to process.
     *
     */
    void dxlist_clean();

    /**
     * Checks if the current packet list is ready to be populated with a burst.
     * If a GPU communication error occurs, err is set to -rte_errno.
     *
     * @param err: Return from communication get status. Output Parameter.
     *
     * @returns True if the packet burst status is RTE_GPU_COMM_LIST_FREE,
     * False otherwise.
     */
    bool rxlist_iswritable(int *ret);

    /**
     * Populates the current packet list with a burst of packets.
     *
     * @param packets: Packet burst to fill the list with.
     * @param npackets: Number of packets in burst.
     *
     * @returns 0 on success, -rte_errno on failure.
     */
    int rxlist_write(struct rte_mbuf **packets, int npackets);

    /**
     * Wrapper for calling a CUDA kernel to process the populated
     * packet burst list. This method also moves the list to the next
     * element to process.
     *
     * @param blocks: Number of blocks to launch on kernel.
     * @param threads: Number of threads to launch per block.
     */
    void rxlist_process(int blocks, int threads);
};
#endif