#include "ft_nmap.h"

void    init_data(t_data *dt, t_parsed_cmd *parsed_cmd)
{
    dt->input_dest          = "";
    dt->act_options         = parsed_cmd->act_options;
    dt->resolved_address    = NULL;
    dt->resolved_hostname   = "";
    dt->socket              = 0;
    dt->dst_port            = 80;
    dt->src_port            = 45555;
    ft_memset(&(dt->local_address),  0, sizeof(struct sockaddr_in));
    ft_memset(&(dt->target_address), 0, sizeof(struct sockaddr_in));
    dt->target_address.sin_family       = AF_INET;
    dt->target_address.sin_port         = 0;
    dt->target_address.sin_addr.s_addr  = INADDR_ANY;
    ft_memset(dt->fds, 0, sizeof(dt->fds));
    dt->fds[0].events       = POLLOUT;
    dt->queue               = NULL;
    dt->threads             = THREADS_NB;     
}

void    add_destination(t_data *dt, char *curr_arg)
{
    if (dt)
        dt->input_dest = curr_arg;
}

void    initialise_data(t_data *dt, t_parsed_cmd *parsed_cmd)
{
    init_data(dt, parsed_cmd);
    init_options_params(dt);
    if (ft_lst_size(parsed_cmd->not_options) != 1)
        exit_error("ft_nmap: usage error: Destination required and only one.\n");
    else
        add_destination(dt, parsed_cmd->not_options->content);
    resolve_address(dt);
    resolve_hostname(dt);
}
