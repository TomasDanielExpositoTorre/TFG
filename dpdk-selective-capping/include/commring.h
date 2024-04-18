#ifndef __COMRING__H__
#define __COMRING__H__

#include "headers.h"

class CommunicationRing
{
protected:
    struct pcap_packet_header *headers;
    int ring_size;
    int burst_size;

public:
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

class LinearCommunicationRing : public CommunicationRing
{
protected:
    int rxi, dxi, pxi;

public:
    /**
     * Constructor method for this object. Creates the necessary elements
     * communication and attaches to a file for packet dumping.
     *
     * @param args: arguments received from user.
     * @param i: Identifier for this object.
     */
    LinearCommunicationRing(struct arguments args, int i) : CommunicationRing(args, i){};
    virtual ~LinearCommunicationRing() = default;

    /**
     * @returns True if the packet list is free, False otherwise.
     */
    virtual bool rxlist_iswritable() = 0;

    /**
     * Populates the current packet list with a burst of packets.
     *
     * @returns The number of packets populated in the list.
     */
    virtual int rxlist_write() = 0;

    /**
     * Notifies the dedicated processing element that the packet list
     * has been populated. Advances the reception pointer to the next
     * list in the ring.
     *
     * @param[in] npackets: Number of packets to process.
     */
    virtual void rxlist_process(int npackets) = 0;

    /**
     * @returns True if the packet list has elements left to dump,
     * False otherwise.
     */
    virtual bool dxlist_isempty() = 0;

    /**
     * @returns True if the packet list is done processing,
     * False otherwise.
     */
    virtual bool dxlist_isreadable() = 0;

    /**
     * Reads the processed packet list, setting the headers and list length
     * values accordingly.
     *
     * @param[out] pkt_headers: pcap-like struct with packet list metadata.
     * @param[out] num_pkts: Number of packets in rte_mbuf packet list.
     *
     * @returns list of packets to dump from the packet ring.
     */
    virtual struct rte_mbuf **dxlist_read(struct pcap_packet_header **pkt_headers, int *num_pkts) = 0;

    /**
     * Restores the packet list to its original state and returns mbufs to the
     * mempool. Notifies the dedicated reception element that the list is free.
     */
    virtual void dxlist_clean() = 0;
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
private:
    struct rte_mbuf ***packet_ring;
    int *nbpackets;
    int *burstate;

    std::mutex tlock;
    int nthreads, tids;
    int subring_size;
    int *rxi, *dxi, *pxi;

public:
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

    /**
     * Schedules the next subring burst to be filled.
     *
     * @param[in] previous: Thread which was populated last.
     *
     * @returns Burst index to populate.
     */
    int rxlist_choosethread(int previous);

    /**
     * Populates a packet list with a burst of packet for the given
     * thread to process.
     *
     * @param[in] thread: Thread identifier.
     *
     * @returns The number of packets populated in the list.
     */
    int rxlist_write(int thread);

    /**
     * Notifies the dedicated processing thread that the packet list
     * has been populated. Advances the reception pointer to the next
     * list in the subring for that thread.
     *
     * @param[in] thread: Thread identifier.
     * @param[in] npackets: Number of packets to process.
     */
    void rxlist_process(int thread, int npackets);

    /**
     * Checks the status of the processing subring for the given
     * thread.
     *
     * @param[in] thread: Thread id.
     *
     * @returns True if the packet list is free, False otherwise.
     */
    bool pxlist_isempty(int thread);

    /**
     * Checks the status of the processing subring for the given
     * thread.
     *
     * @param[in] thread: Thread id.
     *
     * @returns True if the packet list is populated, False otherwise.
     */
    bool pxlist_isready(int thread);

    /**
     * Reads the populated packet list, setting the headers and list length
     * values accordingly.
     *
     * @param[in] thread: Thread id.
     * @param[out] pkt_headers: pcap-like struct with packet list metadata.
     * @param[out] num_pkts: Number of packets in rte_mbuf packet list.
     *
     * @returns list of packets to process from the packet ring.
     */
    struct rte_mbuf **pxlist_read(int thread, struct pcap_packet_header **pkt_headers, int *num_pkts);

    /**
     * Notifies the dedicated dumping element that the list is done processing.
     */
    void pxlist_done(int thread);

    /**
     * @returns True if the packet ring has elements left to dump,
     * False otherwise.
     */
    bool dxlist_isempty();

    /**
     * Schedules the next subring burst to be dumped in disk.
     *
     * @param[in] previous: thread which was dumped last.
     *
     * @returns Burst index to dump.
     */
    int dxlist_choosethread(int previous);

    /**
     * Reads the processed packet list, setting the headers and list length
     * values accordingly.
     *
     * @param[in] thread: Thread id.
     * @param[out] pkt_headers: pcap-like struct with packet list metadata.
     * @param[out] num_pkts: Number of packets in rte_mbuf packet list.
     *
     * @returns list of packets to process from the packet ring.
     */
    struct rte_mbuf **dxlist_read(int thread, struct pcap_packet_header **pkt_headers, int *num_pkts);

    /**
     * Restores the packet list to its original state and returns mbufs to the
     * mempool. Notifies the dedicated reception element that the list is free.
     *
     * @param[in] thread: Thread id.
     */
    void dxlist_clean(int thread);
};

/**
 * @brief Implementation of a communication ring between CPU and NIC.
 *
 * Communication is achieved through a packet burst ring, where:
 * - A reception core populates packet bursts.
 * - A processing core applies selective capping over the populated packets.
 * - A dumping core writes processed packets from this list in pcap format.
 */
    class CpuCommunicationRing : public LinearCommunicationRing
    {
    private:
        struct rte_mbuf ***packet_ring;
        int *nbpackets;
        int *burstate;

    public:
        CpuCommunicationRing(struct arguments args, int i);
        ~CpuCommunicationRing();

        bool rxlist_iswritable();
        int rxlist_write();
        void rxlist_process(int npackets);

        /**
         * @returns True if the packet list is free, False otherwise.
         */
        bool pxlist_isempty();

        /**
         * @returns True if the packet list is populated, False otherwise.
         */
        bool pxlist_isready();

        /**
         * Reads the populated packet list, setting the headers and list length
         * values accordingly.
         *
         * @param[out] pkt_headers: pcap-like struct with packet list metadata.
         * @param[out] num_pkts: Number of packets in rte_mbuf packet list.
         *
         * @returns list of packets to process from the packet ring.
         */
        struct rte_mbuf **pxlist_read(struct pcap_packet_header **pkt_headers, int *num_pkts);

        /**
         * Notifies the dedicated dumping element that the list is done processing.
         */
        void pxlist_done();

        bool dxlist_isempty();
        bool dxlist_isreadable();
        struct rte_mbuf **dxlist_read(struct pcap_packet_header **pkt_headers, int *num_pkts);
        void dxlist_clean();
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
    class GpuCommunicationRing : public LinearCommunicationRing
    {
    private:
        struct rte_gpu_comm_list *comm_list;
        struct rte_mbuf *burst[MAX_BURSTSIZE];
        int qbursts, mbursts;

    public:
        cudaStream_t stream;

        GpuCommunicationRing(struct arguments args, int i);
        ~GpuCommunicationRing();

        bool rxlist_iswritable();
        int rxlist_write();
        void rxlist_process(int npackets);

        bool dxlist_isempty();
        bool dxlist_isreadable();
        struct rte_mbuf **dxlist_read(struct pcap_packet_header **pkt_headers, int *num_pkts);
        void dxlist_clean();
    };
#endif