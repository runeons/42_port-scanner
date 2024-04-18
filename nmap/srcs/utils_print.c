#include "ft_nmap.h"

void print_info(char *msg)
{
    if (g_verbose == ON)
        printf(C_G_BLUE"[INFO]"C_RES"   %s\n", msg);
}

void print_info_int(char *msg, int n)
{
    if (g_verbose == ON)
        printf(C_G_BLUE"[INFO]"C_RES"   %s %d\n", msg, n);
}

void print_info_task(char *msg, int n)
{
    if (g_verbose == ON)
        printf(C_G_GREEN"[INFO]"C_RES"  %s %d\n", msg, n);
}

void print_info_thread(char *msg)
{
    if (VERBOSE_THREAD == ON)
        printf(C_B_YELLOW"[THREAD]"C_RES"   %s\n", msg);
}
