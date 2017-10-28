
#define _XOPEN_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "trie.h"
#include "log.h"

int main()
{
	Trie *root = trie_create();
	printf("%p\n", root);
	trie_insert(root, "2401:aa00:1:1:215:17ff:fedd:929e", 11, -1, NULL, NULL);
	trie_visited(root, -1);
	
	printf("%p\n", root);
	return 0;
}
