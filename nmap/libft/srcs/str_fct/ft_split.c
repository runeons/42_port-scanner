/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_split.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: tsantoni <tsantoni@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/15 12:45:58 by tsantoni          #+#    #+#             */
/*   Updated: 2021/05/18 18:58:15 by tsantoni         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <libft.h>

int	ft_issep(char c, char sep)
{
	if (c == sep)
		return (1);
	return (0);
}

int	ft_countstr(char *s, char sep)
{
	int	i;
	int	n;

	i = 0;
	n = 0;
	while (ft_issep(s[i], sep) == 1)
		i++;
	while (s[i])
	{
		if (ft_issep(s[i], sep) == 0 && (ft_issep(s[i + 1], sep) == 1
				|| s[i + 1] == '\0'))
			n++;
		i++;
	}
	return (n);
}

char	**ft_split(char const *s, char c)
{
	char	**t;
	int		i;
	int		begin;
	int		a;

	i = 0;
	begin = 0;
	a = 0;
	t = mmalloc(sizeof(t) * (ft_countstr((char *)s, c) + 1));
	if (!(t))
		return (NULL);
	while (ft_issep(s[i], c) == 1 && s[i])
		i++;
	while (s[i] && a < ft_countstr((char *)s, c))
	{
		begin = i;
		while (s[i] && a < ft_countstr((char *)s, c) && ft_issep(s[i], c) == 0)
			i++;
		t[a] = ft_substr(s, begin, i - begin);
		a++;
		while (s[i] && a < ft_countstr((char *)s, c) && ft_issep(s[i], c) == 1)
			i++;
	}
	t[a] = NULL;
	return (t);
}
