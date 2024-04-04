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

class CommunicationRing
{
protected:
    struct pcap_packet_header *burst_headers;
    int rxi, dxi;
    int ring_size;

public:
    static volatile bool force_quit;
    static std::mutex write;
    struct queue_stats stats;
    std::mutex npackets, nbytes;
    FILE *pcap_fp;
    volatile bool self_quit;
    int id;
    int burst_size;

    CommunicationRing(struct arguments args, int i);
    ~CommunicationRing();

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
     * @param using_gpu: True if the allocated memory needs to be visible for a GPU.
     */
    static void shmem_register(struct rte_pktmbuf_extmem *ext_mem,
                               struct rte_eth_dev_info *dev_info,
                               bool using_gpu);

    /**
     * Class method that closes a started ethernet device on the given port,
     * and unmaps CPU the memory address on ext_mem from the ethernet device
     * and GPU.
     *
     * @param ext_mem: External buffer data to unmap.
     * @param dev_info: Ethernet device mapped to the buffer.
     * @param port_id: Ethernet device port.
     * @param using_gpu: True if the allocated memory was exposed to a GPU.
     */
    static void shmem_unregister(struct rte_pktmbuf_extmem *ext_mem,
                                 struct rte_eth_dev_info *dev_info,
                                 int port_id, bool using_gpu);
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
class GpuCommunicationRing : public CommunicationRing
{
private:
    struct rte_gpu_comm_list *comm_list;

public:
    struct kernel_arguments kargs;
    cudaStream_t stream;

    /**
     * Constructor method for this object. Creates the necessary elements
     * for CPU-GPU communication and attaches to a file for packet dumping.
     *
     * @param args: arguments received from user.
     * @param i: Identifier for this object.
     */
    GpuCommunicationRing(struct arguments args, int i);
    ~GpuCommunicationRing();

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
    
    /**
     * @returns True if the communication ring has elements left to dump,
     * False otherwise.
     */
    bool dxlist_isempty();

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
     */
    void dxlist_clean();

};

struct capping_arguments
{
    unsigned short ascii_runlen;
    unsigned short ascii_percentage;
};

enum burst_state
{
    BURST_FREE = 0,
    BURST_PROCESSING = 1,
    BURST_DONE = 2
};

class CpuCommunicationRing : public CommunicationRing
{
private:
    struct rte_mbuf ***packet_ring;
    int *nbpackets;
    int *burstate;
    int pxi;

public:
    struct capping_arguments cargs;

    CpuCommunicationRing(struct arguments args, int i);
    ~CpuCommunicationRing();


    bool rxlist_iswritable();
    int rxlist_write();
    void rxlist_process();

    bool pxlist_isempty();
    bool pxlist_isready();
    struct rte_mbuf **pxlist_read(int *num_pkts);
    void pxlist_done();

    bool dxlist_isempty();
    bool dxlist_isreadable();
    struct rte_mbuf **dxlist_read(struct pcap_packet_header *burst_header, int *num_pkts);
    void dxlist_clean();
};
#endif