#include "ft_nmap.h"

void    debug_addrinfo(struct addrinfo *ai)
{
    if (ai != NULL)
    {
        printf(C_B_RED"[DEBUG] addrinfo"C_RES"\n");
        printf("        ai_family: %d\n",   ai->ai_family);
        printf("        ai_socktype: %d\n", ai->ai_socktype);
        printf("        ai_addr: %s\n",     inet_ntoa(((struct sockaddr_in *)ai->ai_addr)->sin_addr));
        printf("\n");
    }
}

void    debug_sockaddr_in(struct sockaddr_in *addr)
{
    if (addr != NULL)
    {
        printf(C_B_RED"[DEBUG] sockaddr_in"C_RES"\n");
        printf("        sin_family: %d\n",              addr->sin_family);
        printf("        sin_port: %d\n",                addr->sin_port);
        printf("        sin_addr.s_addr: %s (%d)\n",    inet_ntoa(addr->sin_addr), addr->sin_addr.s_addr);
        printf("\n");
    }
}

void    bind_socket_to_src_port(t_data *dt, int src_port)
{
    dt->local_address.sin_family        = AF_INET;
    dt->local_address.sin_addr.s_addr   = INADDR_ANY;
    dt->local_address.sin_port          = htons(src_port);
    if (bind(dt->socket, (struct sockaddr *)&dt->local_address, sizeof(dt->local_address)) == -1)
        exit_error_close(dt->socket, "Error binding socket.\n");
}

void    open_main_socket(t_data *dt)
{
    int optval = 64; // TTL_VALUE for IP_TTL socket

    dt->socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (dt->socket < 0)
        exit_error("ft_nmap: socket error: Check that you have the correct rights.\n");
    if (setsockopt(dt->socket, IPPROTO_IP, IP_TTL, &optval, sizeof(optval)) < 0)
        exit_error_close(dt->socket, "ft_nmap: socket error in setting option: Exiting program.%s\n");
    bind_socket_to_src_port(dt, dt->src_port);
    dt->fds[0].fd = dt->socket;

}
