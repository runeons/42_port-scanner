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

void resolve_address(t_data *dt) // check that dest exists and resolve address if input == hostname
{
    struct addrinfo     *resolved_add;
    struct addrinfo     *tmp;

    if (getaddrinfo(dt->input_dest, NULL, NULL, &resolved_add) != 0)
        exit_error("ft_nmap: unknown host\n");
    // debug_addrinfo(resolved_add);
    tmp = resolved_add;
    while (tmp != NULL)
    {
        if ((struct sockaddr_in *)tmp->ai_addr)
            dt->resolved_address = ft_strdup(inet_ntoa(((struct sockaddr_in *)tmp->ai_addr)->sin_addr));
        if (dt->resolved_address == NULL)
            exit_error("ft_nmap: malloc failure.\n");
        tmp = tmp->ai_next;
        break; // useful if many
    }
    freeaddrinfo(resolved_add);
}

void resolve_hostname(t_data *dt) // useful only when input_dest is ip address (vs. hostname)
{
    char    host[MAX_HOSTNAME_LEN];

    ft_bzero(host, MAX_HOSTNAME_LEN);
    if (inet_pton(AF_INET, dt->resolved_address, &(dt->target_address.sin_addr)) <= 0)
        exit_error("ft_nmap: address error: Invalid IPv4 address.\n");
    if (getnameinfo((struct sockaddr*)&(dt->target_address), sizeof(dt->target_address), host, sizeof(host), NULL, 0, 0) != 0)
        exit_error("ft_nmap: address error: The hostname could not be resolved.\n");
    else
    {
        dt->resolved_hostname = ft_strdup(host);
        if (dt->resolved_hostname == NULL)
            exit_error("ft_nmap: malloc failure.\n");
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
