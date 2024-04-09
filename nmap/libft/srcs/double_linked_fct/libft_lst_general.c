/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft_lst_general.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssingevi <ssingevi@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/05/11 11:47:04 by ssingevi          #+#    #+#             */
/*   Updated: 2021/05/18 12:05:49 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

t_lst	*ft_lst_create_node(void *content)
{
	t_lst	*new;

	new = mmalloc(sizeof(t_lst));
	if (!(new))
		return (NULL);
	new->content = content;
	new->next = NULL;
	new->prev = NULL;
	return (new);
}

int	ft_lst_size(t_lst *lst)
{
	int	nb;

	nb = 0;
	while (lst)
	{
		lst = lst->next;
		nb++;
	}
	return (nb);
}

void	ft_lst_iter_content(t_lst *lst, void (*f)(void *))
{
	if (lst)
	{
		while (lst->next)
		{
			if (lst->next == NULL)
				return ;
			if (f)
				f(lst->content);
			lst = lst->next;
		}
	}
	if (f)
		f(lst->content);
}

void	ft_lst_iter_node(t_lst *lst, void (*f)(t_lst *))
{
	if (lst == 0 || f == 0)
		return ;
	while (lst->next)
	{
		f(lst);
		lst = lst->next;
	}
	f(lst);
}
