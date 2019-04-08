from time import sleep
import subprocess
import pymysql


connection = pymysql.connect(host='localhost',
                             user='cs460_test',
                             password='',
                             db='CS460',
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor)

try:

    while 1 :
        __pids = "("
        p = subprocess.Popen(["ps","-aux"], stdout=subprocess.PIPE)
        out = p.stdout.read()
        lines = out.split("\n")
        
        del lines[0]
        
        for line in lines:
            if not line:
                break
            tokens = list(filter(None, line.split(" ")))
            __pid = None
            if tokens:
                __pid = tokens[1]
            if __pids == "(":
                __pids = __pids+ __pid
            else:
                __pids = __pids + "," + __pid

        __pids = __pids + ") "

        if __pids != "()":
            with connection.cursor() as cursor:
                __sql = "update Process_NXDomain_Tracking set is_proc_dead = 1 where is_proc_dead = 0 and pid not in " + __pids
                cursor.execute(__sql)
                connection.commit()

        sleep(1)

finally:
    connection.close()
