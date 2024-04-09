/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstclear.c                                      :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsantoni <tsantoni@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/18 18:44:37 by tsantoni          #+#    #+#             */
/*   Updated: 2021/04/28 12:44:49 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

void	ft_lstclear(t_list **lst, void (*del)(void *))
{
	t_list	*list;
	t_list	*tmp;

	if (del == 0)
		return ;
	tmp = NULL;
	list = *lst;
	while (list->next)
	{
		tmp = list->next;
		del(list->content);
		m_free(list);
		list = tmp;
	}
	if (list->content)
		del(list->content);
	m_free(list);
	*lst = NULL;
}
