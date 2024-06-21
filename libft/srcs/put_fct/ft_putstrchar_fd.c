/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_putstrchar_fd.c                                 :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsantoni <tsantoni@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/16 14:43:57 by tsantoni          #+#    #+#             */
/*   Updated: 2020/06/19 11:44:10 by tsantoni         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

void	ft_putstrchar_fd(char *s, char c, int fd)
{
	ft_putstr_fd(s, fd);
	write(fd, &c, 1);
}
