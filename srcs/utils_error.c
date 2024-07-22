#include "../includes/ft_nmap.h"

void    exit_error_free(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    dprintf(2, C_G_RED"[ERROR] "C_RES"ft_nmap : ");
    vfprintf(stderr, msg, args);
    va_end(args);
    free_all_malloc();
    exit(1);
}

void    exit_error_full_free(t_data *dt, const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    dprintf(2, C_G_RED"[ERROR] "C_RES"ft_nmap : ");
    vfprintf(stderr, msg, args);
    va_end(args);
    close_all_sockets(dt);
    close_handle(&dt->sniffer);
    close_file(&dt->file);
    free_all_malloc();
    exit(1);
}
