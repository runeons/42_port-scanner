#include "../includes/ft_nmap.h"

double deltaT(struct timeval *t1p, struct timeval *t2p)
{
    register double dt;

    dt = (double)(t2p->tv_sec - t1p->tv_sec) * 1000.0 +
         (double)(t2p->tv_usec - t1p->tv_usec) / 1000.0;
    return (dt);
}
