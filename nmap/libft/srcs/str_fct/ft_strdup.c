/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strdup.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsantoni <tsantoni@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/10 17:31:06 by tsantoni          #+#    #+#             */
/*   Updated: 2021/05/18 12:27:23 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

char	*ft_strdup(const char *s1)
{
	char	*cpy;
	int		len;
	int		i;

	len = 0;
	i = 0;
	while (s1[len])
		len++;
	cpy = mmalloc(sizeof(s1) * (len + 1));
	if (!(cpy))
		return (NULL);
	while (i < len)
	{
		cpy[i] = s1[i];
		i++;
	}
	cpy[i] = s1[i];
	return (cpy);
}
