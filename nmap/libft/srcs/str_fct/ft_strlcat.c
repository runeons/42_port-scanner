/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsantoni <tsantoni@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/11 13:34:14 by tsantoni          #+#    #+#             */
/*   Updated: 2019/10/18 14:52:32 by tsantoni         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

size_t	ft_strlcat(char *dst, const char *src, size_t dstsize)
{
	int	i;
	int	j;
	int	len;

	i = 0;
	j = 0;
	len = (int)ft_strlen(dst);
	if (len > (int)dstsize)
		return ((int)ft_strlen(src) + dstsize);
	while (dst[i])
		i++;
	while (src[j] && j < ((int)dstsize - len - 1))
	{
		dst[i] = src[j];
		i++;
		j++;
	}
	dst[i] = '\0';
	return (len + ft_strlen(src));
}
