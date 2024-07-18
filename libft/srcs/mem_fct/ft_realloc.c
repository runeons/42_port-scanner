/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_realloc.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssingevi <ssingevi@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/05/11 12:23:01 by ssingevi          #+#    #+#             */
/*   Updated: 2021/05/18 12:19:36 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

char	*ft_realloc(char *str, int new_size, int old_size)
{
	char	*new;

	new = NULL;
	if (new_size)
	{
		new = ft_memalloc(new_size);
		if (!(new))
			return (NULL);
	}
	if (str && new)
	{
		ft_memcpy((void *)new, str, (size_t)old_size);
		new[old_size] = '\0';
		ft_strdel(&str);
	}
	new[new_size - 1] = '\0';
	return (new);
}
