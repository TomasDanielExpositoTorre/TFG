#include "headers.h"

CpuCommunicationRing::CpuCommunicationRing(struct arguments args, int i) : LinearCommunicationRing(args, i)
{
    rxi = pxi = dxi = 0;

    nbpackets = (int *)malloc(ring_size * sizeof(nbpackets[0]));
    burstate = (int *)calloc(ring_size, sizeof(burstate[0]));
    packet_ring = (struct rte_mbuf ***)malloc(ring_size * sizeof(packet_ring[0]));

    if (nbpackets == NULL || burstate == NULL || packet_ring == NULL)
    {
        fprintf(stderr, "Failed to create memory for cpu packet ring\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < ring_size; i++)
    {
        packet_ring[i] = (struct rte_mbuf **)malloc(burst_size * sizeof(packet_ring[i][0]));
        if (packet_ring[i] == NULL)
        {
            for (int j = i - 1; j >= 0; j--)
                free(packet_ring[j]);
            free(packet_ring);
            free(nbpackets);
            free(burstate);
            fprintf(stderr, "Failed to create memory for cpu packet ring\n");
            exit(EXIT_FAILURE);
        }
    }
}

CpuCommunicationRing::~CpuCommunicationRing()
{
    for (int i = 0; i < ring_size; i++)
        free(packet_ring[i]);
    free(packet_ring);
    free(nbpackets);
    free(burstate);
    free(headers);
}

bool CpuCommunicationRing::rxlist_iswritable()
{
    return burstate[rxi] == BURST_FREE;
}

int CpuCommunicationRing::rxlist_write()
{
    int i = 0;

    while (CommunicationRing::force_quit == false && i < (burst_size - RTE_RXBURST_ALIGNSIZE))
        i += rte_eth_rx_burst(NIC_PORT, id, &(packet_ring[rxi][i]), (burst_size - i));

#ifdef PCAP_NANOSECONDS
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    headers[rxi * burst_size].ts_sec = ts.tv_sec;
    headers[rxi * burst_size].ts_nsec = ts.tv_nsec;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    headers[rxi * burst_size].ts_sec = tv.tv_sec;
    headers[rxi * burst_size].ts_nsec = tv.tv_usec;
#endif

    rxlog.lock();
    stats.packets += i;

    for (int j = 0; j < i; j++)
        stats.total_bytes += packet_ring[rxi][j]->data_len;
    rxlog.unlock();

    return i;
}

void CpuCommunicationRing::rxlist_process(int npackets)
{
    nbpackets[rxi] = npackets;
    burstate[rxi] = BURST_PROCESSING;
    rxi = (rxi + 1) % ring_size;
}

bool CpuCommunicationRing::pxlist_isempty()
{
    return burstate[pxi] == BURST_FREE;
}

bool CpuCommunicationRing::pxlist_isready()
{
    return burstate[pxi] == BURST_PROCESSING;
}

struct rte_mbuf **CpuCommunicationRing::pxlist_read(struct pcap_packet_header **pkt_headers, int *num_pkts)
{
    *num_pkts = nbpackets[pxi];
    *(pkt_headers) = headers + pxi * burst_size;
    return packet_ring[pxi];
}

void CpuCommunicationRing::pxlist_done()
{
    burstate[pxi] = BURST_DONE;
    pxi = (pxi + 1) % ring_size;
}

bool CpuCommunicationRing::dxlist_isempty()
{
    return burstate[dxi] == BURST_FREE;
}

bool CpuCommunicationRing::dxlist_isreadable()
{
    return burstate[dxi] == BURST_DONE;
}

struct rte_mbuf **CpuCommunicationRing::dxlist_read(struct pcap_packet_header **pkt_headers, int *num_pkts)
{
    *(pkt_headers) = headers + burst_size * dxi;
    *num_pkts = nbpackets[dxi];
    return packet_ring[dxi];
}

void CpuCommunicationRing::dxlist_clean()
{
    rte_pktmbuf_free_bulk(packet_ring[dxi], nbpackets[dxi]);
    burstate[dxi] = BURST_FREE;
    dxi = (dxi + 1) % ring_size;
}