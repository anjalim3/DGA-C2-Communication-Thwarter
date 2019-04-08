import urllib2
import time

with open("murofet_dgas.txt") as file:
    for __dga_url in file:
        try:
            contents = urllib2.urlopen("http://"+__dga_url).read()
        except urllib2.URLError:
            pass
        time.sleep(2)
