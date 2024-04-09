#include "nmap.h"

void init_data(t_data *dt)
{
    dt->input_dest          = ft_strdup("1.1.1.1");
    dt->resolved_address    = NULL;
    dt->resolved_hostname   = "";
    dt->socket              = 0;
    dt->dst_port            = 80 ;
    dt->src_port            = 45555 ;
    dt->threads_nb          = 2;
    ft_memset(&(dt->local_address), 0, sizeof(struct sockaddr_in));
    ft_memset(&(dt->target_address), 0, sizeof(struct sockaddr_in));
    dt->target_address.sin_family = AF_INET;
    dt->target_address.sin_port = 0;
    dt->target_address.sin_addr.s_addr = INADDR_ANY;
}

static void    initialise_data(t_data *dt)
{
    init_data(dt);
    resolve_address(dt);
    resolve_hostname(dt);
}

int main(int ac, char **av)
{
    t_data          dt;

    (void)ac;
    (void)av;
    initialise_data(&dt);
    open_main_socket(&dt);
    debug_sockaddr_in(&dt.target_address);
    return (0);
}