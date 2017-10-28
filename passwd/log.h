#ifndef LOG_H
#define LOG_H

void set_proc_title(char *fmt, ...);
void init_set_proc_title(int argc, char *argv[], char *envp[]);
const char *str_time(void);
int init_log(void);
void write_log(const char *msg, ...);

#endif
