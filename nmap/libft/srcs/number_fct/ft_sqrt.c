#include <libft.h>

unsigned int ft_sqrt(unsigned int x)
{
    unsigned int r = x;

    while (r * r > x)
        r = (r + x / r) / 2;
    return r;
}
