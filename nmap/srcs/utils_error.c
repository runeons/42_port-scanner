#include "../includes/ft_nmap.h"

// add file closure when applicable
void exit_error_free(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    dprintf(2, C_G_RED"[ERROR] "C_RES"ft_nmap : ");
    vfprintf(stderr, msg, args);
    va_end(args);
    free_all_malloc();
    exit(1);
}

void exit_error_free_close_all(t_data *dt, const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    dprintf(2, C_G_RED"[ERROR] "C_RES"ft_nmap : ");
    vfprintf(stderr, msg, args);
    va_end(args);
    free_all_malloc();
    (void)dt;
    // close_all_sockets(dt);
    exit(1);
}

void exit_error_free_close_one(int socket, const char *msg, ...)
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

void warning(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    dprintf(2, C_G_MAGENTA"[WARNING] "C_RES"");
    vfprintf(stderr, msg, args);
    va_end(args);
}
