#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "trie.h"
static char ip[64];

Trie *
trie_create()
{
	Trie *root = (Trie *) malloc(sizeof(Trie));

	if (root == NULL)
	{
		write_log("Trie's root Malloc Error.");
		return NULL;
	}

	memset(root, 0x00, sizeof(Trie));
	return root;
}

int
trie_insert(const Trie * root, const char *ip, int device_type, int have_master,
			const char *master_username, const char *master_password)
{
	int i, ilen, n, ulen = 0, plen = 0;
	Trie *c, *p;
	char *s;

	ilen = strlen(ip);

	/* If this device has master user */
	if (have_master != -1)
	{
		ulen = strlen(master_username) + 1;
		plen = strlen(master_password) + 1;
	}

	c = root;
	for (i = 0; i < ilen; i++)
	{
		if (ip[i] >= '0' && ip[i] <= '9')
			n = ip[i] - '0';
		else if (ip[i] >= 'a' && ip[i] <= 'f')
			n = ip[i] - 'a' + 10;
		else if (ip[i] >= 'A' && ip[i] <= 'F')
			n = ip[i] - 'A' + 10;
		else if (ip[i] == '.')
			n = 16;
		else if (ip[i] == ':')
			n = 17;
		//n = ip[i] < '0' ? 10 : (ip[i] - '0');
		if (c->next[n] == NULL)
		{
			p = (Trie *) malloc(sizeof(Trie));

			if (p == NULL)
			{
				write_log("Trie Malloc Error.");
				return -1;
			}

			memset(p, 0x00, sizeof(Trie));
			c->next[n] = p;
		}
		c = c->next[n];
	}

	/* This function is used to update master user */
	if (have_master != -1)
	{
		c->have_master = 1;

		if (c->master_username == NULL)
		{
			s = (char *) malloc(ulen);

			if (s == NULL)
			{
				write_log("Trie's master username Malloc Error.");
				return -1;
			}

			bzero(s, ulen);
			strcpy(s, master_username);
			c->master_username = s;

			s = (char *) malloc(plen);

			if (s == NULL)
			{
				write_log("Trie's master password Malloc Error.");
				return -1;
			}

			bzero(s, plen);
			strcpy(s, master_password);
			c->master_password = s;
		}
		/* Multiple master usernames */
		else if (strcasecmp(c->master_username, master_username))
		{
			write_log("Warning! Multiple master users on device \"%s\".", ip);
		}
	}
	/* This function is used to update device_type */
	else if (device_type != -1)
	{
		c->device_type = device_type;
	}

	return 0;
}

int
trie_search(Trie * root, const char *ip, int *device_type, int *have_master, char *username,
			char *password)
{
	int i, len, n;
	Trie *c;

	len = strlen(ip);
	c = root;

	for (i = 0; i < len; i++)
	{
		if (ip[i] >= '0' && ip[i] <= '9')
			n = ip[i] - '0';
		else if (ip[i] >= 'a' && ip[i] <= 'f')
			n = ip[i] - 'a' + 10;
		else if (ip[i] >= 'A' && ip[i] <= 'F')
			n = ip[i] - 'A' + 10;
		else if (ip[i] == '.')
			n = 16;
		else if (ip[i] == ':')
			n = 17;
		//n = ip[i] < '0' ? 10 : (ip[i] - '0');
		if (c->next[n] == NULL)
			return -1;
		c = c->next[n];
	}

	if (device_type)
		*device_type = c->device_type;
	if (have_master)
		*have_master = c->have_master;
	if (username && c->master_username)
		strcpy(username, c->master_username);
	if (password && c->master_password)
		strcpy(password, c->master_password);

	return 0;
}

int
trie_visited(Trie * root, int step)
{
	int i;

	if (root == NULL)
		return 0;

	for (i = 0; i < 18; i++)
	{
		if (root->next[i])
		{
			if (i >= 0 && i <= 9)
				ip[step + 1] = '0' + i;
			else if (i >= 10 && i <= 15)
				ip[step + 1] = 'a' + i - 10;
			else if (i == 16)
				ip[step + 1] = '.';
			else if (i == 17)
				ip[step + 1] = ':';
			//ip[step + 1] = (i == 10 ? '.' : '0' + i);
			trie_visited(root->next[i], step + 1);
			ip[step + 1] = 0x00;
		}
	}

	/* if( root->master_username ) { write_log( "%s master_user is \"%s\".", ip,
	   root->master_username ); } */
	if (root->have_master)
	{
		write_log("Device \"%s\": type=%d master_user=\"%s\"", ip, root->device_type,
				  root->master_username);
	}
	else if (root->device_type)
	{
		write_log("Device \"%s\": type=%d No master_user.", ip, root->device_type);
	}

	return 0;
}

int
trie_destroy(Trie * root)
{
	int i;
	if (root == NULL)
		return 0;

	for (i = 0; i < 11; i++)
	{
		if (root->next[i])
		{
			trie_destroy(root->next[i]);
		}
	}

	if (root->master_username)
	{
		memset(root->master_username, 0x00, strlen(root->master_username) + 1);
		free(root->master_username);
	}

	if (root->master_password)
	{
		bzero(root->master_password, strlen(root->master_password) + 1);
		free(root->master_password);
	}
	free(root);
	return 0;
}
