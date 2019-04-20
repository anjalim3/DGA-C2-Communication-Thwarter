import urllib2
import time


'''
Simulates domain generation of Murofet version 1

'''
with open("murofet_dgas.txt") as file:
    for __dga_url in file:
        try:
            contents = urllib2.urlopen("http://"+__dga_url).read()
        except urllib2.URLError:
            pass
        time.sleep(2)
