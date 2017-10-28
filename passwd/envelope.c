#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <iconv.h>

#include "mysql.h"
#include "global.h"

extern char type_protocol[64][16];

static int
code_convert(char *from_charset, char *to_charset, char *inbuf, size_t inlen, char *outbuf,
		size_t outlen)
{
	iconv_t cd;
	char **pin = &inbuf;
	char **pout = &outbuf;

	cd = iconv_open(to_charset, from_charset);
	if (cd == 0)
		return -1;

	if (iconv(cd, pin, (size_t *) & inlen, pout, (size_t *) & outlen) == -1)
		return -1;

	iconv_close(cd);
	return 0;
}

static char *
u2g(char *inbuf)
{
	size_t outlen = 1024;
	size_t inlen = strlen(inbuf);
	static char outbuf[1024];

	bzero(outbuf, sizeof(outbuf));
	if (code_convert("UTF-8", "GB2312", inbuf, inlen, outbuf, outlen) == 0)
	{
		return outbuf;
	}
	else
	{
		return inbuf;
	}
}

static int
devices2devices_password(FILE * csvfp)
{
	MYSQL *sql;
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	char buf[256];
	int ret = 0;

	sql = mysql_init(NULL);
	sql =
		mysql_real_connect(sql, config.mysql_address, config.mysql_username, config.mysql_password,
						   config.mysql_database, 0, NULL, 0);

	if (sql == NULL)
		return -1;

	write_log("Devices 2 devices_password.");

	snprintf(buf, sizeof(buf), "set names utf8");
	mysql_query(sql, buf);

	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "DELETE FROM devices_password");

	if (mysql_query(sql, buf) != 0)
	{
		write_log("Delete devices_password table failed.");
		mysql_close(sql);
		return -1;
	}

	bzero(buf, sizeof(buf));

    if (config.udf) {
        snprintf(buf, sizeof(buf),
            "SELECT device_ip,login_method,hostname,username,udf_decrypt(old_password),"
            "udf_decrypt(cur_password),last_update_time,port,device_type FROM devices");
    } else {
        snprintf(buf, sizeof(buf),
            "SELECT device_ip,login_method,hostname,username,aes_decrypt(old_password, \"%s\"),"
            "aes_decrypt(cur_password, \"%s\"),last_update_time,port,device_type FROM devices", aes_key, aes_key);
    }

	if (mysql_query(sql, buf) != 0)
	{
		write_log("SELECT devices table failed.");
		mysql_close(sql);
		return -1;
	}

	res = mysql_store_result(sql);

	fprintf(csvfp, "Hostname,IP,Username,Login Method,Previous Password,Current Password\n");

	while ((row = mysql_fetch_row(res)) != NULL)
	{
		/* bzero( buf, sizeof( buf ) ); snprintf( buf, sizeof( buf ), "INSERT INTO devices_password 
		   (device_ip,login_method,hostname,username,old_password, " \
		   "cur_password,last_update_time,port,device_type)
		   VALUES(\"%s\",%d,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%d,%d)", row[0], atoi( row[1] ),
		   row[2], row[3], row[4], row[5], row[6], atoi( row[7] ), atoi( row[8] ) ); */
		/* add for csv file */
		fprintf(csvfp, "%s,%s,%s,%s,%s,%s\n", u2g(row[2]), row[0], row[3] == NULL ? "" : row[3], type_protocol[atoi(row[1])],
				row[4] == NULL ? "" : row[4], row[5] == NULL ? "" : row[5]);

		/* if( mysql_query( sql, buf ) != 0 ) { write_log( "Insert devices_password table failed."
		   ); ret = -1; continue; } */
	}

	mysql_close(sql);
	return ret;
}

int
insert_passwordkey_table(const char *key, int zip_email_ret, int key_email_ret, const char *zip_file)
{
	MYSQL *sql;
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	char buf[256];

	sql = mysql_init(NULL);
	sql =
		mysql_real_connect(sql, config.mysql_address, config.mysql_username, config.mysql_password,
						   config.mysql_database, 0, NULL, 0);

	if (sql == NULL)
		return -1;

	write_log("Insert passwordkey table.");

	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf),
			 "INSERT INTO passwordkey (key_str,key_date,key_email,zip_email,zip_file) VALUES(\"%s\",now(),%d,%d,\"%s\")",
			 key, key_email_ret, zip_email_ret, zip_file);

	if (mysql_query(sql, buf) != 0)
	{
		write_log("Insert passwordkey table failed.");
		mysql_close(sql);
		return -1;
	}

	mysql_close(sql);
	return 0;
}

static int
get_mail_server_info(char *mail_server, char *mail_account, char *mail_password, char *zip_password)
{
	MYSQL *sql;
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	char buf[256];
	int ret = 0;

	sql = mysql_init(NULL);
	sql =
		mysql_real_connect(sql, config.mysql_address, config.mysql_username, config.mysql_password,
						   config.mysql_database, 0, NULL, 0);

	if (sql == NULL)
		return -1;

	write_log("Fetch mail server information.");

	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "SELECT MailServer,account,password FROM alarm");

	if (mysql_query(sql, buf) != 0)
	{
		write_log("Fetch alarm table failed.");
		mysql_close(sql);
		return -1;
	}

	res = mysql_store_result(sql);

	if ((row = mysql_fetch_row(res)) != NULL)
	{
		if (row[0])
			strcpy(mail_server, row[0]);
		if (row[1])
			strcpy(mail_account, row[1]);
		if (row[2])
			strcpy(mail_password, row[2]);
	}

	/* Add for password_crypt */
	mysql_free_result(res);
	bzero(buf, sizeof(buf));

    if (config.udf) {
        snprintf(buf, sizeof(buf), "select udf_decrypt(password) from password_crypt order by id desc limit 1");
    } else {
        snprintf(buf, sizeof(buf), "select aes_decrypt(password, \"%s\") from password_crypt order by id desc limit 1", aes_key);
    }

	if (mysql_query(sql, buf) != 0)
	{
		write_log("Fetch password_crypt table failed.");
		mysql_close(sql);
		return -1;
	}

	res = mysql_store_result(sql);

	if ((row = mysql_fetch_row(res)) != NULL)
	{
		if (row[0])
			strcpy(zip_password, row[0]);
	}
	mysql_free_result(res);

	mysql_close(sql);
	return 0;
}

static char *
timestamp(void)
{
	static char tstr[32];
	struct tm *tm;
	const char *fmt = "%Y-%m-%d_%H-%M-%S";

	struct timeval tv;
	gettimeofday(&tv, NULL);

	time_t caltime = tv.tv_sec;

	memset(tstr, 0x00, sizeof(tstr));

	if ((tm = localtime(&caltime)) == NULL)
		return (NULL);

	if (strftime(tstr, sizeof(tstr) - 1, fmt, tm) == 0)
		return (NULL);

	return (tstr);
}

int
password_envelope()
{
	char buf[256], sql_filename[256], zip_filename[256], csv_filename[256], zip_password[16], record_filename[256];
	char mail_server[128], serv_account[64], serv_password[64];
	char *ts = timestamp();
	int ret1, ret2;
	FILE *fp;

	bzero(buf, sizeof(buf));
	bzero(sql_filename, sizeof(sql_filename));
	bzero(zip_filename, sizeof(zip_filename));
	bzero(zip_password, sizeof(zip_password));
	bzero(csv_filename, sizeof(csv_filename));
	bzero(mail_server, sizeof(mail_server));
	bzero(serv_account, sizeof(serv_account));
	bzero(serv_password, sizeof(serv_password));

	generate_zip_password(zip_password, 8);
	snprintf(buf, sizeof(buf), "%s/password_%d_%s", TEMP_PATH, getpid(), ts);
	// write_log( "zip_pass:%s, %s", zip_password, buf );
	snprintf(sql_filename, sizeof(sql_filename), "%s.sql", buf);
	snprintf(zip_filename, sizeof(zip_filename), "%s.zip", buf);
	snprintf(csv_filename, sizeof(csv_filename), "%s.csv", buf);
    snprintf(record_filename, sizeof(record_filename), "/opt/freesvr/audit/etc/changepassword/password_%d_%s", getpid(), ts);
	write_log("sfn:%s, zfn:%s, csv filename:%s", sql_filename, zip_filename, csv_filename);

	fp = fopen(csv_filename, "w");
	if (devices2devices_password(fp) == -1)
	{
		fclose(fp);
		return -1;
	}
	fclose(fp);

	get_mail_server_info(mail_server, serv_account, serv_password, zip_password);

	/* bzero( buf, sizeof( buf ) ); snprintf( buf, sizeof( buf ), "mysqldump --opt -u%s -p%s %s
	   devices_password > %s", config.mysql_username, config.mysql_password, config.mysql_database, 
	   sql_filename ); system( buf ); */

	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "zip -j -P %s %s %s > /dev/null", zip_password, zip_filename,
			 csv_filename);
	system(buf);

	//get_mail_server_info(mail_server, serv_account, serv_password, zip_password);

	ret1 =
		lib_send_mail(password_email, mail_server, serv_account, serv_password, "Backup",
					  "CSV Backup", zip_filename);
	write_log("Send CSV file to password account's email %s, ret1 = %d", password_email, ret1);

	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "Password of password_%d_%s.zip is %s", getpid(), ts, zip_password);
	ret2 =
		lib_send_mail(admin_email, mail_server, serv_account, serv_password, "Password", buf, NULL);
	write_log("Send the password of tar to administrator account's email %s, ret2 = %d",
			  admin_email, ret2);

	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "cp %s /opt/freesvr/audit/etc/changepassword/", zip_filename);
	system(buf);

	remove(sql_filename);
	remove(zip_filename);
	remove(csv_filename);

	insert_passwordkey_table(zip_password, ret1 ? 0 : 1, ret2 ? 0 : 1, record_filename);

	return 0;
}
