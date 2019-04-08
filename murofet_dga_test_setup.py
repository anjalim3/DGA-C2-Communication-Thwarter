import urllib2

with open("murofet_dgas.txt") as file:
    for __dga_url in file:
        contents = urllib2.urlopen("http://"+__dga_url).read()
