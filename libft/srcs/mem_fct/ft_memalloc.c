/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memalloc.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssingevi <ssingevi@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/05/11 12:22:52 by ssingevi          #+#    #+#             */
/*   Updated: 2021/05/18 12:15:05 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

void	*ft_memalloc(int size)
{
	char	*new;

	new = mmalloc(size);
	if (!(new))
		return (NULL);
	while (size > 0)
		new[--size] = '\0';
	return (new);
}
