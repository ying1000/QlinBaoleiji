#include <stdio.h>
#include <string.h>
#include "mysql.h"

int
main()
{
	MYSQL *sql_conn;
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	char buf[512];
	int ret = 0;

	sql_conn = mysql_init(NULL);
	sql_conn =
		mysql_real_connect(sql_conn, "127.0.0.1", "freesvr", "freesvr", "audit_sec", 0, NULL, 0);

	/* Fetch policy of password */
	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "SELECT id FROM password_cache "
			 "WHERE generate_time>DATE_SUB(NOW(), INTERVAL %d WEEK) AND password_hash=MD5('%s') AND "
			 "id IN (SELECT id FROM (SELECT id FROM password_cache ORDER BY id DESC LIMIT %d) AS password_cache)",
			 40, "abcd", 2);

	if (mysql_query(sql_conn, buf) == 1)
	{
		fprintf(stderr, "Query error.\n");
		return -1;
	}

	res = mysql_store_result(sql_conn);

	if (res == NULL)
	{
		fprintf(stderr, "[%s:%dL] Error store result: Error %d: %s\n", __FILE__, __LINE__,
				mysql_errno(sql_conn), mysql_error(sql_conn));
		return -1;
	}

	row = mysql_fetch_row(res);
	if (row == NULL)
		fprintf(stderr, "MYSQL_ROW is NULL.\n");
	else if (row[0] == NULL)
		fprintf(stderr, "row[0] = NULL.\n");

	printf("%d\n", mysql_num_rows(res));

	mysql_free_result(res);
	return 0;
}
