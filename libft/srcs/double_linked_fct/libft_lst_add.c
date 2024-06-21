/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft_lst_add.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssingevi <ssingevi@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/05/11 11:46:57 by ssingevi          #+#    #+#             */
/*   Updated: 2021/05/11 11:46:59 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

void	ft_lst_add_node_front(t_lst **alst, t_lst *new)
{
	if (new)
	{
		(*alst)->prev = new;
		new->next = *alst;
		*alst = new;
	}
}

void	ft_lst_add_node_back(t_lst **alst, t_lst *new)
{
	t_lst	*tmp;

	if (*alst == 0)
		*alst = new;
	else
	{
		tmp = *alst;
		while (tmp && tmp->next)
			tmp = tmp->next;
		tmp->next = new;
		new->next = NULL;
		new->prev = tmp;
	}
}
