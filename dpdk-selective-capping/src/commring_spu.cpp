#include "headers.h"

SpuCommunicationRing::SpuCommunicationRing(struct arguments args, int i, int threads) : CommunicationRing(args, i)
{
    pxi = 0;
    tids = 0;
    nthreads = threads;

    rxi = (int *)malloc(nthreads * sizeof(rxi[0]));
    dxi = (int *)malloc(nthreads * sizeof(dxi[0]));
    pxi = (int *)malloc(nthreads * sizeof(pxi[0]));

    npackets = (int *)malloc(ring_size * sizeof(npackets[0]));
    burst_state = (int *)calloc(ring_size, sizeof(burst_state[0]));
    packet_ring = (struct rte_mbuf ***)malloc(ring_size * sizeof(packet_ring[0]));

    if (!rxi || !dxi || !pxi || !npackets || !burst_state || !packet_ring)
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
            free(npackets);
            free(burst_state);
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
    free(npackets);
    free(burst_state);
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
