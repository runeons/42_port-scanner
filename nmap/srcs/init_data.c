#include "ft_nmap.h"

static void resolve_address(t_host *host) // check that dest exists and resolve address if input == hostname
{
    struct addrinfo     *resolved_add;
    struct addrinfo     *tmp;

    if (getaddrinfo(host->input_dest, NULL, NULL, &resolved_add) != 0)
        exit_error("ft_nmap: unknown host\n");
    // debug_addrinfo(resolved_add);
    tmp = resolved_add;
    while (tmp != NULL)
    {
        if ((struct sockaddr_in *)tmp->ai_addr)
            host->resolved_address = ft_strdup(inet_ntoa(((struct sockaddr_in *)tmp->ai_addr)->sin_addr));
        if (host->resolved_address == NULL)
            exit_error("ft_nmap: malloc failure.\n");
        tmp = tmp->ai_next;
        break; // useful if many
    }
    freeaddrinfo(resolved_add);
}

static void resolve_hostname(t_host *host) // useful only when input_dest is ip address (vs. hostname)
{
    char    hostname[MAX_HOSTNAME_LEN];

    ft_bzero(hostname, MAX_HOSTNAME_LEN);
    if (inet_pton(AF_INET, host->resolved_address, &(host->target_address.sin_addr)) <= 0)
        exit_error("ft_nmap: address error: Invalid IPv4 address.\n");
    if (getnameinfo((struct sockaddr*)&(host->target_address), sizeof(host->target_address), hostname, sizeof(hostname), NULL, 0, 0) != 0)
        exit_error("ft_nmap: address error: The hostname could not be resolved.\n");
    else
    {
        host->resolved_hostname = ft_strdup(hostname);
        if (host->resolved_hostname == NULL)
            exit_error("ft_nmap: malloc failure.\n");
    }
}

static void    add_host(t_data *dt, char *curr_arg)
{
    if (dt)
    {
        dt->host.input_dest = curr_arg;
        resolve_address(&dt->host);
        resolve_hostname(&dt->host);
        dt->host.input_dest = curr_arg;
        dt->host.input_dest = curr_arg;
        dt->host.input_dest = curr_arg;
        dt->host.input_dest = curr_arg;
        dt->host.input_dest = curr_arg;

    }
}

static void init_host(t_host *host)
{
    host->input_dest          = "";
    host->resolved_address    = NULL;
    host->resolved_hostname   = "";
    ft_memset(&(host->target_address), 0, sizeof(struct sockaddr_in));
    host->target_address.sin_family       = AF_INET;
    host->target_address.sin_port         = 0;
    host->target_address.sin_addr.s_addr  = INADDR_ANY;
    host->dst_port            = 80;
    host->ports               = NULL;
}

static void    init_data(t_data *dt, t_parsed_cmd *parsed_cmd)
{
    dt->act_options         = parsed_cmd->act_options;
    dt->socket              = 0;
    dt->src_port            = 45555;
    ft_memset(&(dt->local_address),  0, sizeof(struct sockaddr_in));
    ft_memset(dt->fds, 0, sizeof(dt->fds));
    dt->fds[0].events       = POLLOUT;
    dt->queue               = NULL;
    dt->threads             = THREADS_NB;
    ft_memset(&dt->host, 0, sizeof(dt->host));
    init_host(&dt->host);
}

void    initialise_data(t_data *dt, t_parsed_cmd *parsed_cmd)
{
    init_data(dt, parsed_cmd);
    init_options_params(dt);
    if (ft_lst_size(parsed_cmd->not_options) != 1)
        exit_error("ft_nmap: usage error: Destination required and only one.\n");
    else
        add_host(dt, parsed_cmd->not_options->content);
}
