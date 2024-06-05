#ifndef __COMRING__H__
#define __COMRING__H__

#include "headers.h"

class CommunicationRing
{
public:
    static volatile bool force_quit;

    struct pcap_packet_header *headers;
    struct queue_stats stats;

    volatile bool self_quit;
    int ring_size, burst_size;
    int ascii_runlen, ascii_percentage;
    int id;

    FILE *pcap_fp;
    std::mutex rxlog, dxlog;

    /**
     * Constructor method for this object. Creates the necessary elements
     * communication and attaches to a file for packet dumping.
     *
     * @param args: arguments received from user.
     * @param i: Identifier for this object.
     */
    CommunicationRing(struct arguments args, int i);
    ~CommunicationRing();

    /**
     * Class method that allocates and maps CPU memory from ext_mem to
     * the given ethernet device and GPU.
     *
     * This method sets the virtual address of the ext_mem data buffer,
     * but expects ele_size and buf_len values to be initialized.
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
 * @brief Implementation of a communication ring between CPU, GPU and NIC.
 *
 * Communication between the CPU and GPU is done through a packet burst
 * ring, where:
 * - A CPU reception core populates packet bursts.
 * - A GPU kernel applies selective capping over the populated packets.
 * - A CPU dumping core writes processed packets from this list in pcap format.
 */
class GpuCommunicationRing : public CommunicationRing
{
public:
    struct rte_gpu_comm_list *comm_list;
    struct rte_mbuf *burst[MAX_BURSTSIZE];
    int *indices, current, next;
    int nsbr, sbr_size, kernel;
    int rxi, pxi, dxi;
    cudaStream_t stream;

    /**
     * Constructor method for this object. Creates the necessary elements
     * communication and attaches to a file for packet dumping.
     *
     * @param args: arguments received from user.
     * @param i: Identifier for this object.
     */
    GpuCommunicationRing(struct arguments args, int i);
    ~GpuCommunicationRing();

    /**
     * Notifies the dedicated processing element that the packet list
     * has been populated. Advances the reception pointer to the next
     * list in the ring.
     *
     * @param[in] npkts: Number of packets to process.
     */
    void rxlist_process(int npkts);
};

/**
 * @brief Implementation of a communication ring between CPU cores and NIC.
 *
 * Communication is achieved through a packet burst ring, where:
 * - A reception core populates packet bursts for subrings, applying scheduling
 *   through round-robin.
 * - Many processing core apply selective capping over the populated packets.
 * - A dumping core writes processed packets from subrings in pcap format,
 *   applying scheduling through round-robin.
 */
class SpuCommunicationRing : public CommunicationRing
{
public:
    struct rte_mbuf ***packet_ring;
    int *burst_state, *npkts;
    int *rxi, *pxi, *dxi, *sri;
    int nthreads, tids, subring_size;
    std::mutex tlock;

    SpuCommunicationRing(struct arguments args, int i, int threads);
    ~SpuCommunicationRing();

    /**
     * Assigns an identifier to the callee and updates the corresponding value
     * for the next call.
     *
     * @warning This function should be called only once per processing thread.
     *
     * @returns Thread identifier.
     *
     */
    int gettid();
};

/**
 * @brief Implementation of a communication ring between CPU and NIC.
 *
 * Communication is achieved through a packet burst ring, where:
 * - A reception core populates packet bursts.
 * - A processing core applies selective capping over the populated packets.
 * - A dumping core writes processed packets from this list in pcap format.
 */
class CpuCommunicationRing : public CommunicationRing
{
public:
    struct rte_mbuf ***packet_ring;
    int *burst_state, *npkts;
    int rxi, pxi, dxi;

    CpuCommunicationRing(struct arguments args, int i);
    ~CpuCommunicationRing();
};

#endif