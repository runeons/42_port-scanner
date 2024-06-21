/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strjoin.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsantoni <tsantoni@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/11 16:17:36 by tsantoni          #+#    #+#             */
/*   Updated: 2021/05/18 12:27:52 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

char	*ft_strjoin(char const *s1, char const *s2)
{
	int		i;
	int		j;
	char	*buf;

	i = 0;
	j = 0;
	buf = (char *)s1;
	buf = mmalloc(sizeof(char) * (ft_strlen(s1) + ft_strlen(s2)) + 1);
	if (!(buf))
		return (NULL);
	while (s1 && s1[i])
	{
		buf[i] = s1[i];
		i++;
	}
	while (s2[j])
		buf[i++] = s2[j++];
	buf[i] = '\0';
	return (buf);
}
