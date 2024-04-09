/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strjoinfree.c                                   :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssingevi <ssingevi@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/05/11 12:25:03 by ssingevi          #+#    #+#             */
/*   Updated: 2021/05/18 12:28:10 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

char	*ft_strjoinfree(char *s1, char *s2, int tofree)
{
	char	*res;
	int		i;
	int		j;
	int		len;

	i = 0;
	j = 0;
	len = ft_strlen(s1) + ft_strlen(s2) + 1;
	res = mmalloc(sizeof(char) * len);
	if (!(res))
		return (NULL);
	while (s1[i])
	{
		res[i] = s1[i];
		i++;
	}
	while (s2[j] && i < len)
		res[i++] = s2[j++];
	res[i] = '\0';
	if (tofree == 1 || tofree == 3)
		ft_strdel(&s1);
	if (tofree == 2 || tofree == 3)
		ft_strdel(&s2);
	return (res);
}
