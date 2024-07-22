#include "../includes/ft_nmap.h"

int             select_socket_from_pool(t_data *dt, e_scan_type scan_type, int index)
{
    switch (scan_type)
    {
        case UDP:
            return dt->fds[(UDP_INDEX * SOCKET_POOL_SIZE) + (index % SOCKET_POOL_SIZE)].fd;
        case SYN:case ACK:case FIN:case NUL:case XMAS:
            return dt->fds[(TCP_INDEX * SOCKET_POOL_SIZE) + (index % SOCKET_POOL_SIZE)].fd;
        default:
            break;
    }
    return -1;
}

static void     init_socket_pool(t_data *dt, int pool[], int protocol)
{
    int optval = 64; // TTL_VALUE for IP_TTL socket

    for (int i = 0; i < SOCKET_POOL_SIZE; i++)
    {
        pool[i]  = socket(AF_INET, SOCK_RAW, protocol);
        if (pool[i] < 0)
            exit_error_full_free(dt, "socket error: Check that you have the correct rights.\n");
        if (setsockopt(pool[i], IPPROTO_IP, IP_TTL, &optval, sizeof(optval)) < 0)
            exit_error_full_free(dt, "socket error in setting option: Exiting program.\n");
    }
}

void            init_socket(t_data *dt)
{
    init_socket_pool(dt, dt->udp_socket_pool, IPPROTO_UDP);
    init_socket_pool(dt, dt->tcp_socket_pool, IPPROTO_TCP);

    for (int i = 0; i < SOCKET_POOL_SIZE; i++)
    {
        dt->fds[(UDP_INDEX * SOCKET_POOL_SIZE) +  (i % SOCKET_POOL_SIZE)].fd = dt->udp_socket_pool[i];
        dt->fds[(UDP_INDEX * SOCKET_POOL_SIZE) +  (i % SOCKET_POOL_SIZE)].events = POLLOUT;
    }
    for (int i = 0; i < SOCKET_POOL_SIZE; i++)
    {
        dt->fds[(TCP_INDEX * SOCKET_POOL_SIZE) +  (i % SOCKET_POOL_SIZE)].fd = dt->tcp_socket_pool[i];
        dt->fds[(TCP_INDEX * SOCKET_POOL_SIZE) +  (i % SOCKET_POOL_SIZE)].events = POLLOUT;
    }
}
