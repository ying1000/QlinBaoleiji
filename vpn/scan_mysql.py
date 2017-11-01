#!/usr/bin/python

from os import listdir
from os.path import isdir, isfile, join
import MySQLdb
import re
import os
from datetime import datetime

now_dir = datetime.now().strftime('%Y-%m-%d')
print now_dir

move_or_delete = 1 # 0:move 1:delete
move_dir = "/tmp/"

admin_sourceip = {}
with open("/opt/freesvr/vpn/etc/ccd/ipp.txt") as fp:
    for line in fp:
        line = line.rstrip()
        if (len(line) == 0):
            continue

        values = line.split(",")
        admin_sourceip[values[1]]=values[0]

print admin_sourceip

global_cfg = {}
with open("/opt/freesvr/audit/etc/global.cfg") as fp:
    for line in fp:
        line = line.rstrip()
        if (len(line) == 0):
            continue

        values = line.split("=")
        global_cfg[values[0]]=values[1]

db = MySQLdb.connect(global_cfg['mysql-server'],
                     global_cfg['mysql-user'],
                     global_cfg['mysql-pass'],
                     global_cfg['mysql-db']);

cursor = db.cursor();

try:
    cursor.execute("select `serverip`,`sql`,`level`,`mail_alarm`,`dbuser`,`dbname` from db_alarm")
except (MySQLdb.Error, MySQLdb.Warning) as e:
    print e

alarm_config = []
for(serverip,sql,level,mail_alarm,dbuser,dbname) in cursor:
   alarm_config.append([serverip,sql,level,mail_alarm,dbuser,dbname])

print alarm_config

try:
    cursor.execute("select `dbname`,`serverip`,`mail` from db_alarm_mail")
except (MySQLdb.Error, MySQLdb.Warning) as e:
    print e

alarm_mail = []
for (dbname,serverip,mail) in cursor:
    alarm_mail.append([dbname,serverip,mail])


print alarm_mail

try:
    cursor.execute("select max(runtime) from db_mysql")
except (MySQLdb.Error, MySQLdb.Warning) as e:
    print e

for (time) in cursor:
    if time[0] is not None:
        max_runtime = time[0].strftime('%Y-%m-%d %H:%M:%S')
    else:
        max_runtime = 0

print "max_runtime", max_runtime

def handle_file(tFile):
    with open(tFile) as fp:
        for line in fp:
            line = line.rstrip()
            if (len(line) == 0):
                continue

            values = line.split("|")

            if (len(values) == 9):
                datetime, unixtime, sip, sport, dip, dport, dbuser, dbname, action = values[:9]

                datetime = datetime.strip()
                unixtime = unixtime.strip()
                sip = sip.strip()
                sport = sport.strip()
                dip = dip.strip()
                dport = dport.strip()
                dbuser = dbuser.strip()
                dbname = dbname.strip()
                action = action.strip()

                '''
                print "datetime = " + datetime
                print "unixtime = " + unixtime
                print "sip = " + sip
                print "sport = " + sport
                print "dip = " + dip
                print "dport = " + dport
                print "dbuser = " + dbuser
                print "dbname = " + dbname
                print "action =" + action
                '''
                username = ''
                realname = ''
                if(sip in admin_sourceip):
                    username = admin_sourceip[sip]
                    try:
                        cursor.execute("select `realname` from member where `username` = '"+username+"'")
                    except (MySQLdb.Error, MySQLdb.Warning) as e:
                        print e
                    realname=cursor.fetchone()[0]

                sql_state = 'insert into db_mysql (`username`,`realname`,`sourceip`,`runtime`,`serverip`,' \
                            '`sourceport`,`serverport`,`dbuser`,`dbname`,`action`) select ' \
                            '"{}","{}","{}","{}","{}","{}","{}","{}","{}","{}" from db_mysql where exists ' \
                            '(select 1 from mysql.user where "{}" > "{}" limit 1)'.format(username,realname,
                            sip,datetime,dip,sport,dport,dbuser,dbname,action,datetime,max_runtime)

                print sql_state
                cursor.execute(sql_state)
                db.commit()



            elif (len(values) == 12):
                datetime, unixtime, sip, sport, dip, dport, dbuser, \
				dbname, action, query, space, comment = line.split("|")

                datetime = datetime.strip()
                unixtime = unixtime.strip()
                sip = sip.strip()
                sport = sport.strip()
                dip = dip.strip()
                dport = dport.strip()
                dbuser = dbuser.strip()
                dbname = dbname.strip()
                action = action.strip()
                query = query.strip()
                space = space.strip()
                comment = comment.strip()

                '''
                print "datetime = " + datetime
                print "unixtime = " + unixtime
                print "sip = " + sip
                print "sport = " + sport
                print "dip = " + dip
                print "dport = " + dport
                print "user = " + user
                print "dbname = " + dbname
                print "action =" + action
                print "query =" + query
                print "space =" + space
                print "comment =" + comment
                '''

                sql_level = 0
                for(serverip,sql,level,mail_alarm,dbuser_regex,dbname_regex) in alarm_config:
                    if(re.compile(serverip).search(dip)
                    and re.compile(sql).search(query)
                    and re.compile(dbuser_regex).search(dbuser)
                    and re.compile(dbname_regex).search(dbname)):
                        #print "sql_level = " + str(level) + "\n"
                        sql_level = level
                        if(mail_alarm==1):
                            for(dbname_regex2,serverip2,mail_address) in alarm_mail:
                                #print "dbname_regex2 = " + dbname_regex2 + ",serverip2 = " + serverip2 + ",mail_address = " + mail_address + "\n"
                                if(re.compile(serverip2).search(dip)
                                and re.compile(dbname_regex2).search(dbname)):
                                    print "send mail to ", mail_address 
				'''
                                    cursor.execute('insert into mail_sender (`mailto`,`subject`,`msg`,`program`) values ("{}","{}","{}","{}")'.format("lwm_bupt@163.com",
                                    "mysql db audit alarm", dbuser + " run a dangerous command on " + dip , "mysql db auditor"))
                                    db.commit()
                                    mailId = cursor.lastrowid
                                    os.system("/home/wuxiaolong/mail_sender.pl  -i " + str(mailId))
				'''

                username = ''
                realname = ''
                if (sip in admin_sourceip):
                    username = admin_sourceip[sip]
                    try:
                        cursor.execute("select `realname` from member where `username` = '" + username + "'")
                    except (MySQLdb.Error, MySQLdb.Warning) as e:
                        print e
                    realname = cursor.fetchone()[0]

                sql_state = 'insert into db_mysql (`username`,`realname`,`sourceip`,`runtime`,`serverip`,' \
                            '`sourceport`,`serverport`,`dbuser`,`dbname`,`action`,`sql`,`level`) select ' \
                            '"{}","{}","{}","{}","{}","{}","{}","{}","{}","{}","{}","{}" from db_mysql where exists ' \
                            '(select 1 from mysql.user where "{}" > "{}" limit 1)'.format(username,realname,sip,datetime,dip, sport,dport,
                                   dbuser,dbname,action,query,sql_level,datetime,max_runtime)
                print sql_state
                cursor.execute(sql_state)
                db.commit()


def handle_dir(tDir):
    files = [f for f in listdir(tDir) if isfile(join(tDir, f))]
    for tFile in files:
        print tFile
        handle_file(join(tDir, tFile))

logPath = "/home/mysql-dbaudit-log/"
dirs = [d for d in listdir(logPath) if isdir(join(logPath, d))]

for mydir in dirs:
    if mydir != now_dir:
        handle_dir(mydir)
        if move_or_delete==1: #delete
            # os.system("rm -fr " + logPath + mydir)
            print "rm -fr " + logPath + mydir
        elif move_or_delete==0: #move
            # os.system("mv " + mydir + " " + move_dir)
            print "mv " + logPath + mydir + " " + move_dir
