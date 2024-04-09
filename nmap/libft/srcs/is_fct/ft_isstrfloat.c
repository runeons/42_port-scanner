#include <libft.h>

int ft_isstrfloat(const char *s)
{
    int i           = 0;
    int nb_dot      = 0;
    int nb_digit    = 0;

    if (s && s[i] && (s[i] == '-' || s[i] == '+') && s[i + 1])
        i++;
    while (s && s[i])
    {
        if (s[i] == '.')
        {
            nb_dot++;
            if (nb_dot > 1)
                return 0;
        }
        else if (!ft_isdigit(s[i]))
            return 0;
        nb_digit++;
        i++;
    }
    return (nb_digit > 0 && nb_dot <= 1);
}
