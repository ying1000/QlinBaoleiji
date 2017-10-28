#ifndef _TRIE_H_
#define _TRIE_H_

typedef struct _trie
{
	struct _trie *next[18];
	int device_type;
	int have_master;
	char *master_username;
	char *master_password;
} Trie;

extern Trie *trie_create(void);
extern int trie_insert(const Trie *, const char *, int, int, const char *, const char *);
extern int trie_search(Trie *, const char *, int *, int *, char *, char *);
extern int trie_visited(Trie *, int);
extern int trie_destroy(Trie *);

#endif
