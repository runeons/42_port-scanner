#include <libft.h>

float ft_atof(const char *s)
{
    int i;
    float res;
    float fraction;
    int n;

    i = 0;
    res = 0.0f;
    fraction = 0.0f;
    n = 1;
    while ((s[i] >= 9 && s[i] <= 13) || s[i] == 32)
        i++;
    if (s[i] == '+' || s[i] == '-') {
        if (s[i] == '-')
            n = -1;
        i++;
    }
    while (ft_isdigit(s[i])) {
        res = res * 10.0f + (s[i] - '0');
        i++;
    }

    if (s[i] == '.')
    {
        i++;
        float divisor = 10.0f;
        while (ft_isdigit(s[i]))
        {
            fraction += (s[i] - '0') / divisor;
            divisor *= 10.0;
            i++;
        }
    }
    return n * (res + fraction);
}
