/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   libft_lst_print.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: ssingevi <ssingevi@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/05/11 11:47:15 by ssingevi          #+#    #+#             */
/*   Updated: 2021/05/18 18:48:23 by tsantoni         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

/*
** #include <libft.h>
** #include <stdio.h>
**
** void	ft_lst_print_node(t_lst *node)
** {
** 	if (node)
** 	{
** 		if (node->content)
** 			ft_printf("\033[33;01mcontent: [%s]\033[0m\n",
**	 (char *)node->content);
** 		if (node->prev)
** 			ft_printf("\033[32;01m	prev:    [%s]\033[0m\n",
**	 (char *)node->prev->content);
** 		else
** 			ft_printf("\033[32;01m	prev:    [%s]\033[0m\n",
**	 (char *)node->prev);
** 		if (node->next)
** 			ft_printf("\033[31;01m	next:    [%s]\033[0m\n",
**	 (char *)node->next->content);
** 		else
** 			ft_printf("\033[31;01m	next:    [%s]\033[0m\n", (char *)node->next);
** 	}
** }
**
** void	ft_lst_print_content(void *content)
** {
** 	if (content && *(char *)content)
** 		ft_printf("\033[33;01mcontent: [%s]\033[0m\n", (char *)content);
** }
**
** void	ft_lst_print_node_content(t_lst *node)
** {
** 	if (node && node->content)
** 		ft_printf("\033[31;01mcontent: [%s]\033[0m\n", (char *)node->content);
** }
**
** void	ft_lst_print_all_nodes(t_lst *lst)
** {
** 	if (lst)
** 		ft_lst_iter_node(lst, &ft_lst_print_node);
** }
**
** void	ft_lst_print_all_contents(t_lst *lst)
** {
** 	if (lst)
** 		ft_lst_iter_content(lst, &ft_lst_print_content);
** }
**
** void	ft_lst_print_current_var(t_lst *current)
** {
** 	(void)current;
** 	// if (current && current->content)
** 	// if (current->content->name && current->content->value)
** 		// ft_printf("\033[30;01m var : [%s]=[%s]  [%i] \033[0m\n",
** 	((t_var *)current->content)->name, ((t_var *)current->content)->value,
**	 ((t_var *)current->content)->export);
** }
**
** void	ft_lst_print_all_env_vars(t_lst *first_var)
** {
** 	while (first_var && first_var->next)
** 	{
** 		ft_lst_print_current_var(first_var);
** 		first_var = first_var->next;
** 	}
** 	ft_lst_print_current_var(first_var);
** }
*/
