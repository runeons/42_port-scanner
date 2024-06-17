#include "../includes/ft_nmap.h"

void exit_error_free(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    dprintf(2, C_G_RED"[ERROR] "C_RES"");
    vfprintf(stderr, msg, args);
    va_end(args);
    free_all_malloc();
    exit(1);
}

void exit_error(char *msg)
{
    printf(C_G_RED"[ERROR]"C_RES" %s\n", msg);
    exit(1);
}

void exit_error_str(char *msg, char *error)
{
    printf(C_G_RED"[ERROR]"C_RES" %s %s\n", msg, error);
    exit(1);
}

void exit_error_close_socket(char *msg, int socket)
{
    printf(C_G_RED"[ERROR]"C_RES" %s\n", msg);
    close(socket);
    free_all_malloc();
    exit(1);
}

void warning(char *msg)
{
    printf(C_G_MAGENTA"[WARNING]"C_RES" %s\n", msg);
}

void warning_str(char *msg, char *error)
{
    printf(C_G_MAGENTA"[WARNING]"C_RES" %s %s\n", msg, error);
}

void warning_int(char *msg, int nb)
{
    printf(C_G_MAGENTA"[WARNING]"C_RES" %s %d\n", msg, nb);
}
