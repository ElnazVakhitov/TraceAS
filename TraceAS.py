import sys
import os
import re
from urllib.request import urlopen
from prettytable import PrettyTable

reIP = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
reAS = re.compile("[Oo]riginA?S?: *([\d\w]+?)\n")
reCountry = re.compile("[Cc]ountry: *([\w]+?)\n")
reProvider = re.compile("mnt-by: *([\w\d-]+?)\n")


def getIPTraceRT(name: str):
    cmd_line = f"tracert {name}"
    p = os.popen(cmd_line)
    stdout = p.read()
    return reIP.findall(stdout)


def parse(site, reg):
    try:
        a = reg.findall(site)
        return a[0]
    except:
        return ''


def isGreyIp(ip: str):
    return ip.startswith('192.168.') or ip.startswith('10.') or (ip.startswith(
        '172.') and 15 < int(ip.split('.')[1]) < 32)


def getInfbyIP(ip):
    if isGreyIp(ip):
        return ip, '', '', ''
    url = f"https://www.nic.ru/whois/?searchWord={ip}"
    try:
        with urlopen(url) as f:
            site = f.read().decode('utf-8')
            return ip, parse(site, reAS), parse(site, reCountry), \
                   parse(site, reProvider)
    except:
        return ip, '', '', ''


def table(ips):
    th = ["№", "IP", "AS Name", "Country", "Provider"]
    td_data = []
    n = 0
    for i in ips:
        info = getInfbyIP(i)
        td_data.append(n)
        td_data.extend(info)
        n += 1
    columns = len(th)
    table = PrettyTable(th)
    while td_data:
        table.add_row(td_data[:columns])
        td_data = td_data[columns:]
    print(table)


def main():
    if len(sys.argv) < 2:
        print('Usage: python TraceAS.py \'name or ip\'')
        sys.exit(1)
    ips = getIPTraceRT(sys.argv[1])
    table(ips)


if __name__ == '__main__':
    main()
