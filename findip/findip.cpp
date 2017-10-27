#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include </opt/freesvr/sql/include/mysql.h>
#include <sys/types.h>
#include <sys/wait.h>

using namespace std;

int cmdoutput(char* cmdstring, char* buf, int len)  
{      
    int   fd[2];      
    pid_t pid;      
    int   n, count;       
    memset(buf, 0, len);      
    if (pipe(fd) < 0)          
        return -1;      
    if ((pid = fork()) < 0)          
        return -1;      
    else if (pid > 0)     /* parent process */      
    {          
        close(fd[1]);     /* close write end */          
        count = 0;   
        char buffer[1024];       
        n=read(fd[0],buffer,len);
            //printf("buffer:%s , n:%d\n", buffer, n);
        while (n>0)              
        {
            strcat(buf,buffer);
            n=read(fd[0], buffer, len);          
        }
        close(fd[0]);
        if (waitpid(pid, NULL, 0) > 0) {
            //printf("buf:%s\n", buf);
            return 1;
        }
        
    }
    else {
        close(fd[0]);
        if (fd[1] != STDOUT_FILENO) {
            if (dup2(fd[1], STDOUT_FILENO) != STDOUT_FILENO) {
                return -1;
            }
            close(fd[1]);
        }
        if (execl("/bin/sh", "sh", "-c", cmdstring, (char *)0) == -1) {
            return -1;
        }
        close(fd[1]);
    }
    return 0;
}

int find_port(char *port);

int main()
{
    FILE *stream;
    char buf[1024] = {0};
    char str_port[10] = {0};
    stream = popen("sh /root/.vnc/findport.sh", "r");
    fread(buf, sizeof(char), sizeof(buf), stream);
    int port = atoi(buf) + 5900;
    sprintf(str_port, "%d", port);
    find_port(str_port);
    //printf("%s", str_port);
    pclose(stream);
    return 0;
}

int find_port(char *port)
{
    MYSQL mysql;
    MYSQL_RES *res;
    MYSQL_ROW row;
    char buf[256] = {0};

    strcpy(buf, "select ip from vncserver where port=");
    strcat(buf,  port);
    strcat(buf, ";");
    mysql_init(&mysql);
    if (!mysql_real_connect(&mysql, "localhost", "root", NULL, "audit_sec", 3306, NULL, 0)) {
        printf("mysql_real_connect error\n");
        return -1;
    }

    //printf("%s\n", buf);
    if (mysql_real_query(&mysql, buf, strlen(buf))) {
        printf("mysql_real_query error\n");
        return -1;
    }

    res = mysql_store_result(&mysql);
    if (res == NULL) {
        printf("mysql_store_result error\n");
        return -1;
    }
    while ((row = mysql_fetch_row(res))) {
       printf("%s", row[0]); 
    }

#if 0
    //释放锁
    memset(buf, 0, sizeof(buf));
    strcpy(buf, "update vncserver set lock_status=0 where port=");
    strcat(buf, port);
    strcat(buf, ";");
    if (mysql_real_query(&mysql, buf, strlen(buf))) {
        printf("mysql_real_query error\n");
        return -1;
    }
#endif

    mysql_close(&mysql);
    return 0;
}
