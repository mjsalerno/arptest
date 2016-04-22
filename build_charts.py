#!/usr/bin/env python

# import BeautifulSoup
from BeautifulSoup import BeautifulSoup as Soup
import sys

if len(sys.argv) != 2:
    print('bad arg')
    sys.exit(1)

f = open(sys.argv[1],'r')

soup = Soup(f.read())

ul = soup.find('ul')
lis = ul.findAll('li')
for i in lis:
    if 'CPU' in i.text or 'System' in i.text:
        print(i.text)


table = soup.findAll('table', attrs={'class': 'emphasis2 side_by_side_left'})

cpu_stuff = ['', '', '', '']
pkts = 'nope'

for row in table:
    if row == '\n':
        continue
    cells = row.findAll("td")
    title = row.findAll("th")
    if len(title) < 2 or 'Package' not in title[0].find(text=True) and 'Device Name' not in title[1].find(text=True):
        continue

    for i in range(len(cells)):

        if 'Idle' in cells[i].find(text=True):
            cpu_stuff[0] = str(cells[i].find(text=True)).strip() + ' ' + str(cells[i+1].find(text=True)).strip()

        if '800 MHz' in cells[i].find(text=True):
            cpu_stuff[1] = str(cells[i].find(text=True)).strip() + ' ' + str(cells[i+1].find(text=True)).strip()

        if '900 MHz' in cells[i].find(text=True):
            cpu_stuff[2] = str(cells[i].find(text=True)).strip() + ' ' + str(cells[i+1].find(text=True)).strip()

        if '3.00 GHz' in cells[i].find(text=True):
            cpu_stuff[3] = str(cells[i].find(text=True)).strip() + ' ' + str(cells[i+1].find(text=True)).strip()

        '''
        if '800 MHz' in cells[i].find(text=True)\
                or '900 MHz' in cells[i].find(text=True)\
                or '3.00 GHz' in cells[i].find(text=True)\
                or 'Idle' in cells[i].find(text=True):
            #print(title[0].find(text=True))
            cpu_stuff.append(str(cells[i].find(text=True)).strip() + ' ' + str(cells[i+1].find(text=True)).strip())'''

        if 'wlp1s0' in cells[i].find(text=True):
            #print(cells[i].find(text=True))
            pkts = cells[i-1].find(text=True)


for stat in cpu_stuff:
    print(stat)

print(pkts)

