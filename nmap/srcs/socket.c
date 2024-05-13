#include "../includes/ft_nmap.h"

void    bind_socket_to_src_port(t_data *dt, int src_port)
{
    dt->src_address.sin_family        = AF_INET;
    dt->src_address.sin_addr.s_addr   = INADDR_ANY;
    dt->src_address.sin_port          = htons(src_port);
    if (bind(dt->socket, (struct sockaddr *)&dt->src_address, sizeof(dt->src_address)) == -1)
        exit_error_close(dt->socket, "Error binding socket.\n");
}

void    init_socket(t_data *dt)
{
    int optval = 64; // TTL_VALUE for IP_TTL socket

    dt->socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (dt->socket < 0)
        exit_error("ft_nmap: socket error: Check that you have the correct rights.\n");
    if (setsockopt(dt->socket, IPPROTO_IP, IP_TTL, &optval, sizeof(optval)) < 0)
        exit_error_close(dt->socket, "ft_nmap: socket error in setting option: Exiting program.%s\n");
    bind_socket_to_src_port(dt, dt->src_port);
    dt->fds[0].fd = dt->socket;
    g_socket = dt->socket;
}
