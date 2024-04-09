/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_substr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsantoni <tsantoni@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/11 15:06:13 by tsantoni          #+#    #+#             */
/*   Updated: 2021/05/18 12:32:08 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>
#include <stdio.h>

char	*ft_substr(char const *s, unsigned int start, size_t len)
{
	char	*sub;
	int		i;
	int		j;

	i = start;
	j = 0;
	sub = mmalloc(sizeof(char) * len + 1);
	if (!(sub))
		return (0);
	if (start > ft_strlen(s))
	{
		sub[0] = '\0';
		return (sub);
	}
	while (i < ((int)start + (int)len) && s[i])
		sub[j++] = s[i++];
	sub[j] = '\0';
	return (sub);
}
