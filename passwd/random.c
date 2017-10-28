#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#include "mysql.h"
#include "global.h"
#include "random.h"
#include "log.h"

#define RANDOM_TIMES 30

static char alphabet[128];
static int alpha_sum = 0;
static long int seed;

int
set_password_alphabet()
{
	int i;
	struct timeval tv;
	const char others[] = "1234567890!@#$%^&*()-_=+{}[]<>";

	gettimeofday(&tv, NULL);
	seed = (long int) (time(0) / getpid() + tv.tv_usec);

	/* Initial random seed */
	srand48(seed);

	bzero(alphabet, sizeof(alphabet));

	for (i = 0; i < 128; i++)
	{
		if (isalpha(i))
		{
			alphabet[alpha_sum++] = i;
		}
	}
	for (i = 0; i < strlen(others); i++)
	{
		alphabet[alpha_sum++] = others[i];
	}

	return 0;
}

int
fetch_password_policy(MYSQL * sql_conn, int *minlen, int *minalpha, int *minother, int *mindiff,
					  int *maxrepeats, int *histexpire, int *histsize)
{
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	char buf[256];

	/* Fetch policy of password */
	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf),
			 "SELECT minlen,minalpha,minother,mindiff,maxrepeats,histexpire,histsize FROM password_policy ORDER BY id DESC LIMIT 1");

	if (mysql_query(sql_conn, buf) == 1)
	{
		write_log("[%s]Query to mysql Error, Exit.", __func__);
		return -1;
	}

	res = mysql_store_result(sql_conn);

	if (res == NULL)
	{
		write_log("[%s:%dL] Error store result: Error %d: %s\n", __FILE__, __LINE__,
				  mysql_errno(sql_conn), mysql_error(sql_conn));
		return -1;
	}

	row = mysql_fetch_row(res);

	if (row[0] && minlen)
		*minlen = atoi(row[0]);
	if (row[1] && minalpha)
		*minalpha = atoi(row[1]);
	if (row[2] && minother)
		*minother = atoi(row[2]);
	if (row[3] && mindiff)
		*mindiff = atoi(row[3]);
	if (row[4] && maxrepeats)
		*maxrepeats = atoi(row[4]);
	if (row[5] && histexpire)
		*histexpire = atoi(row[5]);
	if (row[6] && histsize)
		*histsize = atoi(row[6]);

	/* Delete expired password history cache */
	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "DELETE FROM password_cache WHERE id NOT IN "
			 "(SELECT id FROM (SELECT id FROM password_cache ORDER BY id DESC LIMIT %d) AS password_cache) "
			 "AND generate_time < DATE_SUB(NOW(), INTERVAL %d WEEK)", atoi(row[6]), atoi(row[5]));

	if (mysql_query(sql_conn, buf) != 0)
	{
		write_log("[%s]: Some error occurred when delete expired password history.");
	}

	mysql_free_result(res);
	return 0;
}

void
password_shuffer(char *password, int plen)
{
	int time = RANDOM_TIMES, i, j;
	char c;

	while (time--)
	{
		i = lrand48() % plen;
		while ((j = lrand48() % plen) == i);
		c = password[i];
		password[i] = password[j];
		password[j] = c;
	}
	if (!isalpha(password[0]))
	{
		for (i = 1; i < plen; i++)
		{
			if (isalpha(password[i]))
			{
				c = password[0];
				password[0] = password[i];
				password[i] = c;
				break;
			}
		}
	}
}

int
password_cache_hit(MYSQL * sql_conn, char *password, int histexpire, int histsize)
{
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	char buf[512];
	int ret = 0;

	/* Fetch policy of password */
	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "SELECT id FROM password_cache "
			 "WHERE generate_time>DATE_SUB(NOW(), INTERVAL %d WEEK) AND password_hash=MD5('%s') AND "
			 "id IN (SELECT id FROM (SELECT id FROM password_cache ORDER BY id DESC LIMIT %d) AS password_cache)",
			 histexpire, password, histsize);

	if (mysql_query(sql_conn, buf) == 1)
	{
		write_log("[%s]Query to mysql Error, Exit.", __func__);
		return -1;
	}

	res = mysql_store_result(sql_conn);

	if (res == NULL)
	{
		write_log("[%s:%dL] Error store result: Error %d: %s\n", __FILE__, __LINE__,
				  mysql_errno(sql_conn), mysql_error(sql_conn));
		return -1;
	}

	row = mysql_fetch_row(res);

	/* Cache miss */
	if (row == NULL)
		ret = 0;
	/* Hit */
	else
		ret = 1;

	mysql_free_result(res);
	return ret;
}

int
password_valid_check(MYSQL * sql_conn, char *new_password, char *old_password,
					 int minlen, int minalpha, int minother, int mindiff, int maxrepeats,
					 int histexpire, int histsize)
{
	int i, c, ret, numlen, numalpha = 0, numother = 0, numdiff = 0, numrepeats = 0;
	int hash[128], repeats[128];

	memset(hash, 0x00, sizeof(hash));
	memset(repeats, 0x00, sizeof(repeats));

	if (strlen(new_password) < minlen)
	{
		write_log("[%s]: The length of new password is too short, minlen = %d", __func__, minlen);
		return -1;
	}

	for (i = 0; i < strlen(old_password); i++)
	{
		hash[(int) old_password[i]] = 1;
	}

	numlen = strlen(new_password);
	for (i = 0; i < numlen; i++)
	{
		c = (int) new_password[i];

		if (isalpha(c))
			numalpha++;
		else
			numother++;

		if (hash[c])
			numdiff++;

		repeats[c]++;
		if (repeats[c] > numrepeats)
			numrepeats = repeats[c];
	}
	numdiff = numlen - numdiff;

	// write_log ("[%s]: old is %s, new is %s", __func__, old_password, new_password);
	write_log("[%s]: minlen=%d, minalpha=%d, minother=%d, mindiff=%d, maxrepeats=%d",
			  __func__, minlen, minalpha, minother, mindiff, maxrepeats);
	write_log("[%s]: numlen=%d, numalpha=%d, numother=%d, numdiff=%d, numrepeats=%d",
			  __func__, numlen, numalpha, numother, numdiff, numrepeats);

	ret = password_cache_hit(sql_conn, new_password, histexpire, histsize);
	if (numlen < minlen || numalpha < minalpha || numother < minother || numdiff < mindiff
		|| numrepeats > maxrepeats)
	{
		write_log("[%s]: The new password is too simple.", __func__);
		return -1;
	}
	else if (ret == -1)
	{
		write_log("[%s]: Some error occured when fetching password_cache table from Mysql.",
				  __func__);
		return -1;
	}
	else if (ret == 1)
	{
		write_log("[%s]: The new password repeated in history cache.", __func__);
		return -1;
	}
	else
	{
		write_log("[%s]: The new password is valid.", __func__);
		return 0;
	}

	return 0;
}

int
specified_password_valid_check(MYSQL * sql_conn, char *old_password, char *new_password)
{
	int minlen, minalpha, minother, mindiff, maxrepeats, histexpire, histsize;

	if (fetch_password_policy
		(sql_conn, &minlen, &minalpha, &minother, &mindiff, &maxrepeats, &histexpire,
		 &histsize) == -1)
	{
		write_log("[%s]: Some error occurred when fetching password_policy table from Mysql.",
				  __func__);
		return -1;
	}
	else
	{
		write_log("[%s]: Fetch password_policy from Mysql successed.", __func__);
	}

	return password_valid_check(sql_conn, new_password, old_password, minlen, minalpha, minother,
								mindiff, maxrepeats, histexpire, histsize);
}

char *
password_generate_at_random(const int *hash, int plen, int minalpha, int minother, int mindiff,
							int maxrepeats)
{
	char *password;
	int i, j, time, repeats[128];

	/* Malloc */
	password = (char *) malloc(PASSWORD_MAX);
	if (password == NULL)
	{
		write_log("[%s]: Out of memory.", __func__);
		return NULL;
	}
	else
	{
		memset(password, 0x00, PASSWORD_MAX);
	}

	memset(repeats, 0x00, sizeof(repeats));

	for (i = 0; i < minalpha; i++)
	{
		time = RANDOM_TIMES;
		while (time-- && hash[(j = lrand48() % 52)] && repeats[j] > maxrepeats);
		password[i] = alphabet[j];
		repeats[j]++;
	}
	for (; i < minalpha + minother; i++)
	{
		time = RANDOM_TIMES;
		while (time-- && hash[(j = lrand48() % (alpha_sum - 52) + 52)] && repeats[j] > maxrepeats);
		password[i] = alphabet[j];
		repeats[j]++;
	}
	for (; i < plen; i++)
	{
		time = RANDOM_TIMES;
		while (time-- && hash[(j = lrand48() % alpha_sum)] && repeats[j] > maxrepeats);
		password[i] = alphabet[j];
		repeats[j]++;
	}
	password_shuffer(password, plen);

	return password;
}

int
generate_random_password(MYSQL * sql_conn, char *old_password, char *p)
{
	int i, plen, minlen, minalpha, minother, mindiff, maxrepeats, histexpire, histsize;
	char *new_password;
	int hash[128];

	/* Initial hash table */
	memset(hash, 0x00, sizeof(hash));
	for (i = 0; i < strlen(old_password); i++)
	{
		hash[(int) old_password[i]] = 1;
	}

	if (fetch_password_policy
		(sql_conn, &minlen, &minalpha, &minother, &mindiff, &maxrepeats, &histexpire,
		 &histsize) == -1)
	{
		write_log("[%s]: Some error occurred when fetching password_policy table from Mysql.",
				  __func__);
		return -1;
	}
	else
	{
		write_log("[%s]: Fetch password_policy from Mysql successed.", __func__);
	}

	minlen = minlen > (minalpha + minother) ? minlen : (minalpha + minother);
	plen = minlen > 12 ? minlen : 12;

	if (plen > PASSWORD_MAX)
	{
		write_log("[%s]: minlen = %d, is longer than the size of password buffer.", __func__,
				  minlen);
		return -1;
	}

	for (i = 0; i < RANDOM_TIMES; i++)
	{
		new_password =
			password_generate_at_random(hash, minlen, minalpha, minother, mindiff, maxrepeats);
		if (new_password == NULL)
		{
			return -1;
		}

		if (!password_valid_check
			(sql_conn, new_password, old_password, minlen, minalpha, minother, mindiff, maxrepeats,
			 histexpire, histsize))
			break;
	}

	if (p && i < RANDOM_TIMES)
	{
		write_log("[%s]: Generate valid new password successed.", __func__);
		strncpy(p, new_password, plen);
		free(new_password);
		return 0;
	}
	else
	{
		write_log("[%s]: Iteration %d times, but could not generate valid password.", __func__,
				  RANDOM_TIMES);
		free(new_password);
		return -1;
	}

	return 0;
}

int
generate_zip_password(char *p, int length)
{
	int i, j, sum = 0;
	char password[16], alpha[128];

	bzero(password, sizeof(password));
	for (i = 0; i < 128; i++)
	{
		if (isalnum(i))
		{
			alpha[sum++] = i;
		}
	}

	for (i = 0; i < length; i++)
	{
		j = lrand48() % sum;
		password[i] = alpha[j];
	}

	if (p)
	{
		strncpy(p, password, length);
	}
	else
	{
		return -1;
	}

	return 0;
}
