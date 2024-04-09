/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsantoni <tsantoni@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/11 12:27:38 by tsantoni          #+#    #+#             */
/*   Updated: 2021/05/18 12:25:56 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

char	*ft_strnstr(const char *haystack, const char *needle, size_t len)
{
	int	i;
	int	j;
	int	a;

	i = 0;
	if (ft_strlen(needle) == 0)
		return ((char *)haystack);
	while (haystack[i] && i < (int)len)
	{
		j = 0;
		if (haystack[i] == needle[j])
		{
			a = i;
			while (needle[j] == haystack[i] && i < (int)len)
			{
				if (needle[j + 1] == '\0')
					return (&((char *)haystack)[a]);
				i++;
				j++;
			}
			i = a;
		}
		i++;
	}
	return (0);
}
