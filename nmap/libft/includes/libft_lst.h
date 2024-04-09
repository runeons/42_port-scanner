/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft_lst.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssingevi <ssingevi@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/05/11 12:13:24 by ssingevi          #+#    #+#             */
/*   Updated: 2021/05/18 12:03:50 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_LST_H
# define LIBFT_LST_H

# include <libft.h>

# define MALLOC		1
# define FREE		2
# define FREE_ALL	3

typedef struct s_lst
{
	void			*content;
	struct s_lst	*next;
	struct s_lst	*prev;
}					t_lst;

t_lst	*ft_lst_create_node(void *content);
int		ft_lst_size(t_lst *lst);
void	ft_lst_iter_content(t_lst *lst, void (*f)(void *));
void	ft_lst_iter_node(t_lst *lst, void (*f)(t_lst *));

void	ft_lst_print_node(t_lst *node);
void	ft_lst_print_content(void *content);
void	ft_lst_print_node_content(t_lst *node);
void	ft_lst_print_all_nodes(t_lst *lst);
void	ft_lst_print_all_contents(t_lst *lst);

void	ft_lst_print_current_var(t_lst *current);
void	ft_lst_print_all_env_vars(t_lst *first_var);

void	ft_lst_add_node_front(t_lst **alst, t_lst *new);
void	ft_lst_add_node_back(t_lst **alst, t_lst *new);

t_lst	*ft_lst_get_node_at_index(t_lst **alst, int index);
t_lst	*ft_lst_get_previous_node(t_lst *current);
t_lst	*ft_lst_get_next_node(t_lst *current);
t_lst	*ft_lst_get_last_node(t_lst **alst);
t_lst	*ft_lst_get_node_before_last(t_lst **alst);

void	ft_del(void **to_del);
void	ft_lst_del_node(t_lst **alst, t_lst *to_del, void (*del)(void **));
void	ft_lst_del_node_at_index(t_lst **alst, int index);
void	ft_lst_del_first_node(t_lst **alst);
void	ft_lst_del_last_node(t_lst **alst);

#endif
