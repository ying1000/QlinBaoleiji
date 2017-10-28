#ifndef _LIST_H_
#define _LIST_H_

#include "global.h"

typedef struct _list_node
{
	struct _list_node *next;
	int element;
} List_node;
typedef struct _list_node List_head;

typedef struct _candidate_node
{
	struct _candidate_node *next;
	struct _info servinfo;
} Candidate_node;
typedef struct _candidate_node Candidate_head;

typedef struct _command
{
	struct _command *next;
	char *string;
	int echo;
	int execution;
} Command;

typedef struct _modify_info
{
	struct _modify_info *next;
	struct _info *servinfo;
} Modify_info;

typedef struct _login
{
	struct _login *next;
	struct _modify_info *minfo;
} Login;

#define COMMAND_MAX 8

extern List_head *list_create(void);
extern int list_insert(List_head *, int);
extern int list_destroy(List_head *);
extern Candidate_head *candidate_create(void);
extern int candidate_insert(Candidate_head *, const Info *);
extern int candidate_printf(Candidate_head *);
extern int candidate_delete(Candidate_node *, Candidate_node *);
extern int candidate_destroy(Candidate_head *);
extern char **execv_argument_create(const char *, const char *, const char *, int, int);
extern int execv_argument_distroy(char **);
extern Command *command_list_creat(int, int, const char *, const char *, const char *, const char *, const char *);
extern int command_list_destroy(Command *);

#endif
