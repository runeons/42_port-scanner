/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line.h                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsantoni <tsantoni@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/12/09 10:27:40 by tsantoni          #+#    #+#             */
/*   Updated: 2021/04/26 19:01:19 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#ifndef GET_NEXT_LINE_H
# define GET_NEXT_LINE_H

# ifndef BUFFER_SIZE
#  define BUFFER_SIZE 1
# endif

# include <stdlib.h>
# include <unistd.h>
# include <libft.h>

int		get_next_line(int fd, char **line);
int		ft_strlen_gnl(char *s);
char	*ft_calloc_gnl(int size);
void	ft_strdel(char **s);
char	*ft_strjoinfree(char *s1, char *s2, int tofree);
int		ft_haseol(char *line);
void	ft_cut_line_create_tokeep(char *line, char *tokeep);

#endif
