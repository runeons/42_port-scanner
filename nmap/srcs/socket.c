#include "../includes/ft_nmap.h"

// void    bind_socket_to_src_port(t_data *dt, int src_port)
// {
//     dt->src_address.sin_family        = AF_INET;
//     dt->src_address.sin_addr.s_addr   = INADDR_ANY;
//     dt->src_address.sin_port          = htons(src_port);
//     if (bind(dt->socket, (struct sockaddr *)&dt->src_address, sizeof(dt->src_address)) == -1)
//         exit_error_close(dt->socket, "Error binding socket.\n");
// }

static void init_socket_pool(int pool[], int protocol){
    int optval = 64; // TTL_VALUE for IP_TTL socket

    for (int i = 0; i < SOCKET_POOL_SIZE; i++)
    {
        pool[i]  = socket(AF_INET, SOCK_RAW, protocol);
        if (pool[i] < 0)
            exit_error("ft_nmap: socket error: Check that you have the correct rights.\n");
        if (setsockopt(pool[i], IPPROTO_IP, IP_TTL, &optval, sizeof(optval)) < 0)
            exit_error_close(pool[i], "ft_nmap: socket error in setting option: Exiting program.%s\n");
    }
}

void    init_socket(t_data *dt)
{
    init_socket_pool(dt->icmp_socket_pool, IPPROTO_ICMP);
    init_socket_pool(dt->udp_socket_pool, IPPROTO_UDP);
    init_socket_pool(dt->tcp_socket_pool, IPPROTO_TCP);

    for (int i = 0; i < NFDS; i++){
        dt->fds[i].fd = dt->icmp_socket_pool[i];
        dt->fds[i].events = POLLOUT;
    }
    dt->socket = dt->icmp_socket_pool[0];
}
