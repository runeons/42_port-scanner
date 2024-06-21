/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsantoni <tsantoni@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/15 17:23:31 by tsantoni          #+#    #+#             */
/*   Updated: 2021/05/18 12:21:52 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

int	ft_countchars(int n)
{
	int	nb;
	int	sign;

	sign = n;
	nb = 0;
	if (n == 0)
		return (1);
	while (n != 0)
	{
		n = n / 10;
		nb++;
	}
	if (sign < 0)
		return (nb + 1);
	return (nb);
}

char	*ft_itoa(int n)
{
	char	*s;
	int		i;
	int		div;
	long	nb;

	i = 0;
	div = 1;
	nb = n;
	s = mmalloc(sizeof(char) * ft_countchars((int)nb) + 1);
	if (!(s))
		return (NULL);
	if (nb < 0)
	{
		s[i++] = '-';
		nb = -nb;
	}
	while (nb / div >= 10)
		div *= 10;
	while (div > 0)
	{
		s[i++] = (nb / div) % 10 + '0';
		div /= 10;
	}
	s[i] = '\0';
	return (s);
}
