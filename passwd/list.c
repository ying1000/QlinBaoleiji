#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "list.h"
#include "log.h"

List_head *
list_create()
{
	List_head *root;
	root = (List_head *) malloc(sizeof(List_head));

	if (root == NULL)
	{
		write_log("Malloc List_head error.");
		return NULL;
	}
	else
	{
		memset(root, 0x00, sizeof(List_head));
	}

	return root;
}

int
list_insert(List_head * root, int e)
{
	List_node *p = root, *c;

	c = (List_node *) malloc(sizeof(List_node));

	if (c == NULL)
	{
		write_log("Malloc List_node error.");
		return -1;
	}

	c->next = NULL;
	c->element = e;

	while (p->next)
	{
		p = p->next;
	}
	p->next = c;

	return 0;
}

int
list_destroy(List_head * root)
{
	List_node *p = root, *q;

	while (p)
	{
		q = p;
		p = p->next;
		free(q);
	}

	return 0;
}

Candidate_head *
candidate_create()
{
	Candidate_head *p;
	p = (Candidate_head *) malloc(sizeof(Candidate_head));

	if (p == NULL)
	{
		write_log("Malloc Candidate_head error.");
		return NULL;
	}
	else
	{
		memset(p, 0x00, sizeof(Candidate_head));
	}

	return p;
}

int
candidate_insert(Candidate_head * root, const Info * n)
{
	Candidate_node *p = root, *c;

	c = (Candidate_node *) malloc(sizeof(Candidate_node));

	if (c == NULL)
	{
		write_log("Malloc Candidate_node error.");
		return -1;
	}

	/* Set value for new node */
	c->next = NULL;
	memcpy(&(c->servinfo), n, sizeof(Info));

	while (p->next)
	{
		p = p->next;
	}
	p->next = c;

	return 0;
}

int
candidate_delete(Candidate_node * previous, Candidate_node * current)
{
	previous->next = current->next;
	list_destroy((List_head *) ((current->servinfo).id_list));
	free(current);
	return 0;
}

/*int candidate_printf( Candidate_head *root )
{
	Candidate_node *p = root->next;
	Info *ip = NULL;

	while( p )
	{
		ip = &( p->servinfo );
		write_log( "%s@%s protocol:%d automodify:%d", ip->device_username,
				ip->device_serverip, ip->device_ptcl, ip->auto_modify );
		p = p->next;
	}

	return 0;
}*/

int
candidate_destroy(Candidate_head * root)
{
	Candidate_node *p, *q;

	if (root == NULL)
		return 0;

	p = root->next;

	while (p)
	{
		q = p;
		p = p->next;
		list_destroy((List_head *) ((q->servinfo).id_list));
		execv_argument_distroy((q->servinfo).argv);
		command_list_destroy((q->servinfo).input);
		free(q);
	}

	return 0;
}

char **
execv_argument_create(const char *ip, const char *username, const char *password, int protocol,
					  int port)
{
	char **argv, para[64];
	int i = 0, j = 0;
	int len = 512;
	//int len = USERNAME_MAX > PASSWORD_MAX ? USERNAME_MAX : PASSWORD_MAX;

	if ((argv = (char **) malloc(sizeof(char *) * 16)) == NULL)
	{
		write_log("Malloc (char **) execv argv failed.");
		return NULL;
	}

	for (i = 0; i < 16; i++)
	{
		if ((argv[i] = (char *) malloc(sizeof(char) * len)) == NULL)
		{
			for (j = 0; j < i; j++)
			{
				if (argv[j] != NULL)
					free(argv[j]);
			}

			if (argv != NULL)
				free(argv);

			write_log("Malloc (char *) execv argv failed.");
			return NULL;
		}
		else
		{
			memset(argv[i], 0x00, len);
		}
	}

	i = -1;

	if (protocol < 3)
	{
		strcpy(argv[++i], "autossh");
	}
	else
	{
		strcpy(argv[++i], "telnet");
	}

	/* SSH1 */
	if (protocol == SSH1_PROTOCOL)
	{
		strcpy(argv[++i], "-1");
	}

	/* SSH pseudo tty */
	// if( protocol == SSH2_PROTOCOL )
	if (protocol < TELNET_PROTOCOL)
	{
		strcpy(argv[++i], "-tt");
	}

	strcpy(argv[++i], ip);

	/* Add port */
	/* Telnet */
	if (protocol == TELNET_PROTOCOL)
	{
		snprintf(argv[++i], len, "%d", port);
	}
	/* SSH */
	else
	{
		strcpy(argv[++i], "-p");
		snprintf(argv[++i], len, "%d", port);
	}

	/* Add -l username if username is not empty */
	if (protocol < TELNET_PROTOCOL && username != NULL && strlen(username) != 0)
	{
		strcpy(argv[++i], "-l");
		strcpy(argv[++i], username);
	}

	/* Add -z password if protocol is SSH */
	if (protocol < TELNET_PROTOCOL)
	{
		strcpy(argv[++i], "-z");
		strcpy(argv[++i], password);

		bzero(para, sizeof(para));
		snprintf(para, sizeof(para), "-oConnectTimeout=%d", config.timeout);
		strcpy(argv[++i], para);

        //strcpy(argv[++i], "2>/dev/null");
	}

	argv[++i] = (char *) 0;

	return argv;
}

int
execv_argument_distroy(char **argv)
{
	int i = 0;

	if (argv == NULL)
		return 0;

	while (i < 16 && argv[i])
	{
		free(argv[i]);
		i++;
	}

	free(argv);
	return 0;
}

Command *
command_list_creat(int protocol, int have_master, const char *username, const char *pass1,
				   const char *pass2, const char *master_username, const char *master_password)
{
	int i, slen = USERNAME_MAX * 2;
	Command *p[COMMAND_MAX];

	for (i = 0; i < COMMAND_MAX; i++)
	{
		p[i] = (Command *) malloc(sizeof(Command));

		if (p[i] == NULL)
		{
			write_log("Malloc command structure failed.");
			command_list_destroy(p[0]);
			return NULL;
		}

		memset(p[i], 0x00, sizeof(Command));

		if (i)
			p[i - 1]->next = p[i];

		p[i]->string = (char *) malloc(slen);

		if (p[i]->string == NULL)
		{
			write_log("Malloc command string failed.");
			command_list_destroy(p[0]);
			return NULL;
		}
		else
		{
			memset(p[i]->string, 0x00, slen);
		}

	}

	i = -1;

	/* Entry Telnet password */
	if (protocol == TELNET_PROTOCOL)
	{
		if (have_master == 1)
		{
			strcpy(p[++i]->string, master_username);
			p[i]->echo = 1;
			p[i]->execution = TELNET_PROTOCOL;
			strcpy(p[++i]->string, master_password);
			p[i]->echo = 0;
			p[i]->execution = TELNET_PROTOCOL;
		}
		else
		{
			strcpy(p[++i]->string, username);
			p[i]->echo = 1;
			p[i]->execution = TELNET_PROTOCOL;
			strcpy(p[++i]->string, pass1);
			p[i]->echo = 0;
			p[i]->execution = TELNET_PROTOCOL;
		}
	}
#if 0
	if (have_master == 0)
	{
		strcpy(p[++i]->string, "passwd");
		p[i]->echo = 1;
		p[i]->execution = 1;

		/* Entry current password */
		strcpy(p[++i]->string, pass1);
		p[i]->echo = 0;
		p[i]->execution = 1;
	}
	else
	{
		/* This is root account, don't entry current password */
		snprintf(p[++i]->string, slen, "sudo passwd %s", username);
		p[i]->echo = 3;
		p[i]->execution = 1;

		/* Maybe entry sudo password */
		strcpy(p[++i]->string, master_password);
		p[i]->echo = 0;
		p[i]->execution = 1;
	}
#else
    if (have_master == 0)
    {
        snprintf(p[++i]->string, slen, "sudo passwd %s", username);
        p[i]->echo = 3;
        p[i]->execution = 1;

        /* Entry current password */
        strcpy(p[++i]->string, pass1);
        p[i]->echo = 0;
        p[i]->execution = 1;
    }
    else
    {
        /* This is root account, don't entry current password */
        snprintf(p[++i]->string, slen, "passwd %s", username);
        p[i]->echo = 1;
        p[i]->execution = 1;

        /* Maybe entry sudo password 
        strcpy(p[++i]->string, master_password);
        p[i]->echo = 0;
        p[i]->execution = 1; */
    }
#endif

	/* Entry new password */
	strcpy(p[++i]->string, pass2);
	p[i]->echo = 0;
	p[i]->execution = 1;

	/* Retype new password */
	strcpy(p[++i]->string, pass2);
	p[i]->echo = 0;
	p[i]->execution = 1;

	/* Echo $? get passwd return value */
	strcpy(p[++i]->string, "echo $?");
	p[i]->echo = 1;
	p[i]->execution = 1;

	/* Exit strcpy( p[++i]->string, "exit" ); p[i]->echo = 1; p[i]->execution = 1; */
	return p[0];
}

int
command_list_destroy(Command * root)
{
	Command *p, *q;

	p = root;

	while (p)
	{
		q = p;
		p = p->next;

		if (q->string)
			free(q->string);

		free(q);
	}

	return 0;
}

static Modify_info *
modify_info_create()
{
	Modify_info *root;
	root = (Modify_info *) malloc(sizeof(Modify_info));

	if (root == NULL)
	{
		write_log("Malloc the root of Modify info list failed.");
		return NULL;
	}
	else
	{
		memset(root, 0x00, sizeof(Modify_info));
	}

	return root;
}

Login *
login_list_create()
{
	Login *root;
	root = (Login *) malloc(sizeof(Login));

	if (root == NULL)
	{
		write_log("Create the root of Login list failed.");
		return NULL;
	}
	else
	{
		memset(root, 0x00, sizeof(Login));
		root->minfo = modify_info_create();

		if (root->minfo == NULL)
			return NULL;
	}

	return root;
}

int
modify_info_insert(Modify_info * root, Info * info)
{
	Modify_info *p = root, *c;

	while (p->next)
	{
		p = p->next;
	}

	c = (Modify_info *) malloc(sizeof(Modify_info));

	if (c == NULL)
	{
		write_log("Malloc Modify info failed.");
		return -1;
	}
	else
	{
		memset(c, 0x00, sizeof(Modify_info));
		p->next = c;
		c->servinfo = info;
	}

	return 0;
}

int
login_list_insert(Login * root, Candidate_node * cnode)
{
	Login *p = root, *c;
	Info *psi, *csi;

	csi = &(cnode->servinfo);

	while (p->next)
	{
		p = p->next;

		if (p->minfo->next == NULL)
		{
			write_log("The element of Login node is NULL.");
			return -1;
		}
		else
		{
			psi = (p->minfo->next)->servinfo;

			/* */
			if (psi->have_master == 1 && strcmp(psi->device_serverip, csi->device_serverip) == 0)
			{
				modify_info_insert(p->minfo, csi);
				return 0;
			}
		}

	}

	c = login_list_create();

	if (c == NULL)
	{
		write_log("Malloc Login node failed.");
		return -1;
	}

	modify_info_insert(c->minfo, csi);
	p->next = c;
	return 0;
}
