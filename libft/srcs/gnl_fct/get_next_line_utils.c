/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line_utils.c                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsantoni <tsantoni@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/12/09 09:58:43 by tsantoni          #+#    #+#             */
/*   Updated: 2021/05/18 12:10:12 by ssingevi         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

int	ft_strlen_gnl(char *s)
{
	int	i;

	i = 0;
	while (s[i])
		i++;
	return (i);
}

char	*ft_calloc_gnl(int size)
{
	char	*res;
	int		i;

	i = 0;
	res = mmalloc(sizeof(char) * size + 1);
	if (!(res))
		return (NULL);
	while (i < size)
		res[i++] = '\0';
	return (res);
}

int	ft_haseol(char *line)
{
	int	i;

	i = 0;
	while (line[i])
	{
		if (line[i] == '\n')
			return (1);
		i++;
	}
	return (0);
}

void	ft_cut_line_create_tokeep(char *line, char *tokeep)
{
	int	i;
	int	j;

	i = 0;
	j = 0;
	while (line && line[i] != '\n')
		i++;
	line[i] = '\0';
	if (line[i + 1])
		i++;
	while (line[i])
	{
		tokeep[j] = line[i];
		i++;
		j++;
	}
	tokeep[j] = '\0';
}
