#include "../includes/ft_nmap.h"

int             select_socket_from_pool(t_data *dt, e_scan_type scan_type, int index)
{
    switch (scan_type)
    {
        case ICMP:
            //printf("ICMP INDEX: %d\n", (ICMP_INDEX * SOCKET_POOL_SIZE) +  (index % SOCKET_POOL_SIZE));
            return dt->fds[(ICMP_INDEX * SOCKET_POOL_SIZE) + (index % SOCKET_POOL_SIZE)].fd;
        case UDP:
            //printf("UDP INDEX: %d\n", (UDP_INDEX * SOCKET_POOL_SIZE) +  (index % SOCKET_POOL_SIZE));
            return dt->fds[(UDP_INDEX * SOCKET_POOL_SIZE) + (index % SOCKET_POOL_SIZE)].fd;
        case SYN:case ACK:case FIN:case NUL:case XMAS:
            //printf("TCP INDEX: %d\n", (TCP_INDEX * SOCKET_POOL_SIZE) + (index % SOCKET_POOL_SIZE));
            return dt->fds[(TCP_INDEX * SOCKET_POOL_SIZE) + (index % SOCKET_POOL_SIZE)].fd;
        default:
            warning("Invalid scan_type in select_socket_from_pool.\n");
            break;
    }
    return -1;
}

static void     init_socket_pool(int pool[], int protocol)
{
    int optval = 64; // TTL_VALUE for IP_TTL socket

    for (int i = 0; i < SOCKET_POOL_SIZE; i++)
    {
        pool[i]  = socket(AF_INET, SOCK_RAW, protocol);
        if (pool[i] < 0)
            exit_error_free("socket error: Check that you have the correct rights.\n");
        if (setsockopt(pool[i], IPPROTO_IP, IP_TTL, &optval, sizeof(optval)) < 0)
            exit_error_free_close_one(pool[i], "socket error in setting option: Exiting program.\n");
    }
}

void            init_socket(t_data *dt)
{
    init_socket_pool(dt->icmp_socket_pool, IPPROTO_ICMP);
    init_socket_pool(dt->udp_socket_pool, IPPROTO_UDP);
    init_socket_pool(dt->tcp_socket_pool, IPPROTO_TCP);

    for (int i = 0; i < SOCKET_POOL_SIZE; i++)
    {
        dt->fds[(ICMP_INDEX * SOCKET_POOL_SIZE) +  (i % SOCKET_POOL_SIZE)].fd = dt->icmp_socket_pool[i];
        dt->fds[(ICMP_INDEX * SOCKET_POOL_SIZE) +  (i % SOCKET_POOL_SIZE)].events = POLLOUT;
    }
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
