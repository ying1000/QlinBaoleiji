#ifndef _RANDOM_H_
#define _RANDOM_H_

#include "mysql.h"

extern int set_password_alphabet(void);
extern int generate_random_password(MYSQL *, char *, char *);

#endif
