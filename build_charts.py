import BeautifulSoup
from BeautifulSoup import BeautifulSoup as Soup

file = open('2016/t4-1.html','r')

soup = Soup(file.read())

ul = soup.find('ul')
lis = ul.findAll('li')
for i in lis:
    if 'CPU' in i.text or 'System' in i.text:
        print(i.text)


table = soup.findAll('table', attrs={'class': 'emphasis2 side_by_side_left'})

for row in table:
    if row == '\n':
        continue
    cells = row.findAll("td")
    title = row.findAll("th")
    if len(title) < 2 or 'Package' not in title[0].find(text=True) and 'Device Name' not in title[1].find(text=True):
        continue

    for i in range(len(cells)):
        if '800 MHz' in cells[i].find(text=True)\
                or '900 MHz' in cells[i].find(text=True)\
                or '3.00 GHz' in cells[i].find(text=True)\
                or 'Idle' in cells[i].find(text=True):
            #print(title[0].find(text=True))
            print(str(cells[i].find(text=True)) + ' ' + str(cells[i+1].find(text=True)))

        if 'wlp1s0' in cells[i].find(text=True):
            #print(cells[i].find(text=True))
            print(cells[i-1].find(text=True))
