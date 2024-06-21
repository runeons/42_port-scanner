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
