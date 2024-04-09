#include <libft.h>

int ft_ishex(char *s, int size)
{
    for (int i = 0; i < size; i++)
    {
        if (ft_strchr(HEX_CHARS, s[i]) == NULL)
            return 0;
    }
    return 1;
}