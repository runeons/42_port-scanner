/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft_lst_get.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssingevi <ssingevi@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/05/11 11:47:09 by ssingevi          #+#    #+#             */
/*   Updated: 2021/05/11 11:49:56 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

t_lst	*ft_lst_get_node_at_index(t_lst **alst, int index)
{
	t_lst	*tmp;
	int		i;

	i = -1;
	tmp = *alst;
	while (++i < index && tmp->next)
		tmp = tmp->next;
	if (i != index)
		return (NULL);
	return (tmp);
}

t_lst	*ft_lst_get_previous_node(t_lst *current)
{
	if (current->prev && current->prev->content)
		current = current->prev;
	return (current);
}

t_lst	*ft_lst_get_next_node(t_lst *current)
{
	if (current->next)
		current = current->next;
	return (current);
}

t_lst	*ft_lst_get_last_node(t_lst **alst)
{
	t_lst	*tmp;

	tmp = NULL;
	if (alst && *alst)
		tmp = ft_lst_get_node_at_index(alst, ft_lst_size(*alst) - 1);
	return (tmp);
}

t_lst	*ft_lst_get_node_before_last(t_lst **alst)
{
	t_lst	*tmp;

	tmp = NULL;
	if (alst && *alst)
		tmp = ft_lst_get_node_at_index(alst, ft_lst_size(*alst) - 2);
	return (tmp);
}
