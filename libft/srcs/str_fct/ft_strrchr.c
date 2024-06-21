/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strrchr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsantoni <tsantoni@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/10 14:31:23 by tsantoni          #+#    #+#             */
/*   Updated: 2021/05/18 12:30:37 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

char	*ft_strrchr(const char *s, int c)
{
	int	n;

	n = 0;
	while (s[n] != '\0')
		n++;
	while (n >= 0)
	{
		if (s[n] != (char)c)
			n--;
		else
			return (&((char *)s)[n]);
	}
	return (NULL);
}
