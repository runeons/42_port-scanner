/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft_malloc_free.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsantoni <tsantoni@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/05/11 12:08:06 by tsantoni          #+#    #+#             */
/*   Updated: 2021/05/18 18:55:27 by tsantoni         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>
#include <stdio.h>

// t_list	*g_libft.all_malloc;

static t_global	g_libft = { 0, NULL };

void	*mmalloc(unsigned int size)
{
	void	*new;
	t_list	*list;

	new = malloc(size + 1);
	if (!(new))
	{
		free_all_malloc();
		ft_putstr_fd("allocation error", 2);
		exit(1);
	}
	list = (t_list *)malloc(sizeof(t_list));
	if (!(list))
	{
		free_all_malloc();
		ft_putstr_fd("allocation error", 2);
		exit(1);
	}
	ft_bzero(new, size);
	list->content = new;
	list->next = g_libft.all_malloc;
	g_libft.all_malloc = list;
	return (new);
}

int	free_all_malloc(void)
{
	t_list	*prev;

	while (g_libft.all_malloc)
	{
		free(g_libft.all_malloc->content);
		prev = g_libft.all_malloc;
		g_libft.all_malloc = g_libft.all_malloc->next;
		free(prev);
	}
	return (0);
}

int	mfree(void **to_free)
{
	t_list	**indir;
	t_list	*f;

	if (!*to_free)
		return (0);
	indir = &g_libft.all_malloc;
	while (*indir && (*indir)->content != *to_free)
		indir = &((*indir)->next);
	f = *indir;
	if (f)
	{
		*indir = (*indir)->next;
		free(f->content);
	}
	free(f);
	*to_free = NULL;
	return (0);
}

int	m_free(void *ptr)
{
	return (mfree(&ptr));
}
