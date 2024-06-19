#include "../includes/ft_nmap.h"

void    info(char *color, const char *msg, ...)
{
    if (!ft_strcmp(color, C_THREADS) && !V_THREADS)
        return;
    if (!ft_strcmp(color, C_TASKS) && !V_TASKS)
        return;
    if (!ft_strcmp(color, C_GENERIC) && !V_GENERIC)
        return;
    if (!ft_strcmp(color, C_SOCKET) && !V_SOCKET)
        return;
    if (!ft_strcmp(color, C_SNIFFER) && !V_SNIFFER)
        return;
    va_list args;
    va_start(args, msg);
    dprintf(2, "%s[INFO]"C_RES"     ", color);
    vfprintf(stderr, msg, args);
    va_end(args);
}

// add file closure when applicable
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
    pcap_close(dt->sniffer.handle);
    close_all_sockets(dt);
    close_file(&dt->file);
    free_all_malloc();
    exit(1);
}

void    exit_error_free_close_one(int socket, const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    dprintf(2, C_G_RED"[ERROR] "C_RES"ft_nmap : ");
    vfprintf(stderr, msg, args);
    va_end(args);
    free_all_malloc();
    close(socket);
    exit(1);
}

void    important_warning(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    dprintf(2, C_B_RED"[SHOULD NOT APPEAR]"C_RES" ");
    vfprintf(stderr, msg, args);
    va_end(args);
}

void    warning(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    dprintf(2, C_G_MAGENTA"[WARNING] "C_RES"");
    vfprintf(stderr, msg, args);
    va_end(args);
}
