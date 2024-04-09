/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnew.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssingevi <ssingevi@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/05/11 12:25:48 by ssingevi          #+#    #+#             */
/*   Updated: 2021/05/18 12:30:23 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

char	*ft_strnew(int i)
{
	char	*str;

	str = mmalloc(sizeof(char) * (i + 1));
	if (!(str))
		return (NULL);
	ft_bzero(str, i + 1);
	return (str);
}
