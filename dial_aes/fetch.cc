#include "golbal.h"

CANDIDATE *
fetch_candidate_list()
{
	MYSQL_RES *res;
	MYSQL_ROW row;
	char buf[512];

	snprintf(buf, sizeof(buf), "SELECT id,username,device_ip,port,login_method,"\
			"udf_decrypt(cur_password),udf_decrypt(old_password),udf_decrypt(new_passowrd) "\
			"FROM devices");

	if (mysql_query(sql_conn, buf) != 0)
	{
		printf("%s\n", mysql_error(sql_conn));
		return -1;
	}

	if ((res = mysql_store_result(sql_conn)) == NULL)
	{
		printf("%s\n", mysql_error(sql_conn));
		return -1;
	}
	
	row = mysql_fetch_row(res);

	while ((row = mysql_fetch_row(res)) != NULL)
	{
		candidate.id = atoi(row[0]);
		strcpy(candidate.username, row[1]);
		strcpy(candidate.ipaddr, row[2]);
		candidate.port = atoi(row[3]);
		candidate.login_method = atoi(row[4]);
		strcpy(candidate.cur_password, row[5]);
		strcpy(candidate.old_password, row[6]);
		strcpy(candidate.new_password, row[7]);
	}

	mysql_free_result(res);
	return ret;
}



	
