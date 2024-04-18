#include "headers.h"

SpuCommunicationRing::SpuCommunicationRing(struct arguments args, int i, int threads) : CommunicationRing(args, i)
{
    pxi = 0;
    tids = 0;
    nthreads = threads;

    rxi = (int *)malloc(nthreads * sizeof(rxi[0]));
    dxi = (int *)malloc(nthreads * sizeof(dxi[0]));
    pxi = (int *)malloc(nthreads * sizeof(pxi[0]));

    nbpackets = (int *)malloc(ring_size * sizeof(nbpackets[0]));
    burstate = (int *)calloc(ring_size, sizeof(burstate[0]));
    packet_ring = (struct rte_mbuf ***)malloc(ring_size * sizeof(packet_ring[0]));

    if (!rxi || !dxi || !pxi || !nbpackets || !burstate || !packet_ring)
    {
        fprintf(stderr, "Failed to create memory for cpu packet ring\n");
        exit(EXIT_FAILURE);
    }

    subring_size = ring_size / nthreads;

    for (int i = 0; i < nthreads; i++)
        rxi[i] = pxi[i] = dxi[i] = (subring_size * i);

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
            free(rxi);
            free(dxi);
            free(pxi);
            fprintf(stderr, "Failed to create memory for cpu packet ring\n");
            exit(EXIT_FAILURE);
        }
    }

}
SpuCommunicationRing::~SpuCommunicationRing()
{
    for (int i = 0; i < ring_size; i++)
        free(packet_ring[i]);
    free(packet_ring);
    free(nbpackets);
    free(burstate);
    free(headers);
    free(rxi);
    free(dxi);
    free(pxi);
}

int SpuCommunicationRing::gettid()
{
    int i;
    tlock.lock();
    i = tids++;
    tlock.unlock();
    return i;
}


int SpuCommunicationRing::rxlist_choosethread(int previous)
{
    int thread = previous;

    while (force_quit == false && burstate[rxi[thread]] != BURST_FREE)
        thread = (thread + 1) % nthreads;

    if (force_quit)
        return -1;

    return thread;
}

int SpuCommunicationRing::rxlist_write(int thread)
{
    int i = 0;

    while (force_quit == false && i < (burst_size - RTE_RXBURST_ALIGNSIZE))
        i += rte_eth_rx_burst(NIC_PORT, id, &(packet_ring[rxi[thread]][i]), (burst_size - i));

#ifdef PCAP_NANOSECONDS
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    headers[rxi * burst_size].ts_sec = ts.tv_sec;
    headers[rxi * burst_size].ts_nsec = ts.tv_nsec;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    headers[rxi[thread] * burst_size].ts_sec = tv.tv_sec;
    headers[rxi[thread] * burst_size].ts_nsec = tv.tv_usec;
#endif

    rxlog.lock();
    stats.packets += i;

    for (int j = 0; j < i; j++)
        stats.total_bytes += packet_ring[rxi[thread]][j]->data_len;
    rxlog.unlock();

    return i;
}

void SpuCommunicationRing::rxlist_process(int thread, int npackets)
{
    nbpackets[rxi[thread]] = npackets;
    burstate[rxi[thread]] = BURST_PROCESSING;
    rxi[thread] = ((rxi[thread] + 1) % subring_size) + thread * subring_size;
}

bool SpuCommunicationRing::pxlist_isempty(int thread)
{
    return burstate[pxi[thread]] == BURST_FREE;
}

bool SpuCommunicationRing::pxlist_isready(int thread)
{
    return burstate[pxi[thread]] == BURST_PROCESSING;
}

struct rte_mbuf **SpuCommunicationRing::pxlist_read(int thread, int *num_pkts, struct pcap_packet_header **pkt_headers)
{
    *num_pkts = nbpackets[pxi[thread]];
    *(pkt_headers) = headers + pxi[thread] * burst_size;
    return packet_ring[pxi[thread]];
}

void SpuCommunicationRing::pxlist_done(int thread)
{
    burstate[pxi[thread]] = BURST_DONE;
    pxi[thread] = ((pxi[thread] + 1) % subring_size) + thread * subring_size;
}

bool SpuCommunicationRing::dxlist_isempty()
{
    for (int i = 0; i < nthreads; i++)
        if (burstate[dxi[i]] != BURST_FREE)
            return false;

    return true;
}

int SpuCommunicationRing::dxlist_choosethread(int previous)
{
    int thread = (previous + 1) % nthreads;

    while (self_quit == false && burstate[dxi[thread]] != BURST_DONE)
        thread = (thread + 1) % nthreads;

    if (self_quit == true && dxlist_isempty())
        return -1;

    return thread;
}

struct rte_mbuf **SpuCommunicationRing::dxlist_read(int thread, struct pcap_packet_header **pkt_headers, int *num_pkts)
{
    *(pkt_headers) = headers + burst_size * dxi[thread];
    *num_pkts = nbpackets[dxi[thread]];
    return packet_ring[dxi[thread]];
}

void SpuCommunicationRing::dxlist_clean(int thread)
{
    rte_pktmbuf_free_bulk(packet_ring[dxi[thread]], nbpackets[dxi[thread]]);
    burstate[dxi[thread]] = BURST_FREE;
    dxi[thread] = ((dxi[thread] + 1) % subring_size) + thread * subring_size;
}