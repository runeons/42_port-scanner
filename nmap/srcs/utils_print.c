#include "nmap.h"

void print_info(char *msg)
{
    printf(C_G_BLUE"[INFO]"C_RES" %s\n", msg);
}

void print_info_int(char *msg, int n)
{
    printf(C_G_BLUE"[INFO]"C_RES" %s %d\n", msg, n);
}
