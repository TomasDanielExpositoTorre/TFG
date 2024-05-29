#ifndef __COMRING__H__
#define __COMRING__H__

#include "headers.h"

class CommunicationRing
{
public:
    struct pcap_packet_header *headers;
    int ring_size;
    int burst_size;
    static volatile bool force_quit;
    static std::mutex write;
    struct queue_stats stats;
    struct arguments args;
    std::mutex rxlog, dxlog;
    FILE *pcap_fp;
    volatile bool self_quit;
    int id;

    /**
     * Constructor method for this object. Creates the necessary elements
     * communication and attaches to a file for packet dumping.
     *
     * @param args: arguments received from user.
     * @param i: Identifier for this object.
     */
    CommunicationRing(struct arguments args, int i);
    virtual ~CommunicationRing() = default;

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
private:
    struct rte_gpu_comm_list *comm_list;
    struct rte_mbuf *burst[MAX_BURSTSIZE];
    int qbursts, mbursts;
    int rxi, dxi, pxi;

public:
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
     * @returns True if the packet list is free, False otherwise.
     */
    bool rxlist_iswritable();

    /**
     * Populates the current packet list with a burst of packets.
     *
     * @returns The number of packets populated in the list.
     */
    int rxlist_write();

    /**
     * Notifies the dedicated processing element that the packet list
     * has been populated. Advances the reception pointer to the next
     * list in the ring.
     *
     * @param[in] npackets: Number of packets to process.
     */
    void rxlist_process(int npackets);

    /**
     * @returns True if the packet list has elements left to dump,
     * False otherwise.
     */
    bool dxlist_isempty();

    /**
     * @returns True if the packet list is done processing,
     * False otherwise.
     */
    bool dxlist_isreadable();

    /**
     * Reads the processed packet list, setting the headers and list length
     * values accordingly.
     *
     * @param[out] pkt_headers: pcap-like struct with packet list metadata.
     * @param[out] num_pkts: Number of packets in rte_mbuf packet list.
     *
     * @returns list of packets to dump from the packet ring.
     */
    struct rte_mbuf **dxlist_read(struct pcap_packet_header **pkt_headers, int *num_pkts);

    /**
     * Restores the packet list to its original state and returns mbufs to the
     * mempool. Notifies the dedicated reception element that the list is free.
     */
    void dxlist_clean();
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
    int *burst_state;
    int *npackets;

    std::mutex tlock;
    int nthreads, tids;
    int subring_size;
    int *rxi, *dxi, *pxi;
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
    int *npackets;
    int *burst_state;

    CpuCommunicationRing(struct arguments args, int i);
    ~CpuCommunicationRing();
};



#endif