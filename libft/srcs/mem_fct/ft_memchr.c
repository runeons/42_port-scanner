/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsantoni <tsantoni@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/09 17:23:47 by tsantoni          #+#    #+#             */
/*   Updated: 2019/10/16 17:20:19 by tsantoni         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

void	*ft_memchr(const void *s, int c, size_t n)
{
	size_t	i;
	void	*t;

	i = 0;
	t = (void *)s;
	while (i < n)
	{
		if (((unsigned char *)s)[i] == (unsigned char)c)
			return (t + i);
		else
			i++;
	}
	return (NULL);
}
