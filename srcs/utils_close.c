#include "../includes/ft_nmap.h"

void     close_all_sockets(t_data *dt)
{
    // for (int i = 0; i < SOCKET_POOL_SIZE; i++)
    //     close(dt->icmp_socket_pool[i]);
    for (int i = 0; i < SOCKET_POOL_SIZE; i++)
        close(dt->udp_socket_pool[i]);
    for (int i = 0; i < SOCKET_POOL_SIZE; i++)
        close(dt->tcp_socket_pool[i]);
}

void     close_file(FILE **file)
{
    if (file && *file)
    {
        fclose(*file);
        *file = NULL;
    }
}

void     close_handle(t_sniffer *sniffer)
{
    if (sniffer->handle)
    {
        pcap_close(sniffer->handle);
        sniffer->handle = NULL;
    }
}
