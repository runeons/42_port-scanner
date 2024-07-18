/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstdelone.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsantoni <tsantoni@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/18 17:32:16 by tsantoni          #+#    #+#             */
/*   Updated: 2021/04/28 12:44:58 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

void	ft_lstdelone(t_list *lst, void (*del)(void*))
{
	if (lst == 0 || del == 0)
		return ;
	if (lst->content)
		del(lst->content);
	m_free(lst);
}
