#include "headers.h"

CpuCommunicationRing::CpuCommunicationRing(struct arguments args, int i) : CommunicationRing(args, i)
{
    rxi = pxi = dxi = 0;
    npkts = (int *)malloc(ring_size * sizeof(npkts[0]));
    burst_state = (int *)calloc(ring_size, sizeof(burst_state[0]));
    packet_ring = (struct rte_mbuf ***)malloc(ring_size * sizeof(packet_ring[0]));

    if (npkts == NULL || burst_state == NULL || packet_ring == NULL)
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
            free(npkts);
            free(burst_state);
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
    free(npkts);
    free(burst_state);
    free(headers);
}