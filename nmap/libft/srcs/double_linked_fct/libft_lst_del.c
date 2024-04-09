/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft_lst_del.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssingevi <ssingevi@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/05/11 11:47:01 by ssingevi          #+#    #+#             */
/*   Updated: 2021/05/11 12:15:31 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

void	ft_del(void **to_del)
{
	if (to_del && *to_del)
	{
		m_free(*to_del);
		*to_del = NULL;
	}
}

void	ft_lst_del_node(t_lst **alst, t_lst *to_del, void (*del)(void **))
{
	t_lst	*tmp;

	if (to_del && del)
	{
		tmp = *alst;
		if (tmp == to_del)
		{
			if (tmp->next)
			{
				tmp->next->prev = NULL;
				*alst = tmp->next;
			}
		}
		else
		{
			if (to_del->next)
				to_del->next->prev = to_del->prev;
			if (to_del->prev)
				to_del->prev->next = to_del->next;
		}
		if (to_del->content)
			del(&to_del->content);
	}
}

void	ft_lst_del_node_at_index(t_lst **alst, int index)
{
	t_lst	*to_del;

	to_del = ft_lst_get_node_at_index(alst, index);
	ft_lst_del_node(alst, to_del, ft_del);
}

void	ft_lst_del_first_node(t_lst **alst)
{
	ft_lst_del_node_at_index(alst, 0);
}

void	ft_lst_del_last_node(t_lst **alst)
{
	ft_lst_del_node_at_index(alst, ft_lst_size(*alst) - 1);
}
