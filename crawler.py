from platform import system as iden
from webbrowser import open as op_w
from os.path import isfile
from random import choice
from colorama import Fore
from json import loads
from os import remove
from sys import argv
import ast , requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
w = Fore.WHITE
c = Fore.CYAN
g = Fore.GREEN
r = Fore.RED
y = Fore.YELLOW
colors = [w, c, y, g, r]
def pass_to_burp():
    proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    names_f = ["urls.txt" , "hostnames.txt" , "Web_archieves_urls.txt" , "results_crawlers.txt"]
    for file_n in names_f:
        if isfile(file_n):
            with open(file_n , 'r')as f:
                for url in f.readlines():
                    url = url.rstrip()
                    req = requests.get(url ,verify=False , proxies=proxies)
def banner():
 colors = [w , r , g , c , y]
 print (f"""{choice(colors)}       
                                      _           
                                     | |          
               ___ _ __ __ ___      _| | ___ _ __ 
              / __| '__/ _` \ \ /\ / / |/ _ \ '__|
             | (__| | | (_| |\ V  V /| |  __/ |   
              \___|_|  \__,_| \_/\_/ |_|\___|_|V1.0
                               
                    Coded By : Ali Mansour                         

 """)  
def del_repeat( name ):
    for name_ in name:
        if isfile(name_):
            with open(name_ , 'r')as f:
                data = set(f.readlines())
                fx = open(name_ , 'w')
                for line in data :
                    fx.write(line.rstrip() + '\n')
                fx.close()
def otx_crawls( target ):
    req = loads(requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/url_list?limit=10000000&page=1").text)["url_list"]
    f_u = open("urls.txt" , 'w')
    f_h = open("hostnames.txt" , 'w')
    for i in req:
        if not i.get("httpcode") in range(499,599):
            print (choice(colors))
            print (f"URL : {i.get('url')}")
            print (f"HOSTNAME : {str(i.get('hostname'))}\n")
            print (f'{choice(colors)}-----------------------------------------')
            f_u.write (i.get("url") + '\n')
            f_h.write (i.get("hostname") + '\n')
    f_u.close()
    f_h.close()
def web_arch( target ):
    with open ("Web_archieves_urls.txt" , 'a')as f2:
        x = loads(requests.get("https://web.archive.org/cdx/search?url="+target+"%2F&matchType=prefix&collapse=urlkey&output=json&fl=original%2Cmimetype%2Ctimestamp%2Cendtimestamp%2Cgroupcount%2Cuniqcount&filter=!statuscode%3A%5B45%5D..&limit=100000&_=1547318148315").text)
        for url in x:
            f2.write (url[0] + '\n')
def crawls( target ):
    req = requests.get(f"http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=*.{target}/*&output=json")
    with open(f"{target}.json" , 'a')as f:
        f.write(req.text)
    f_r = open("results_crawlers.txt" , 'a')
    for x in open(f"{target}.json",'r').readlines():
        x = x.rstrip()
        try:
            res = ast.literal_eval(x) # You Can Use eval Func Without this Lib :)
            print (choice(colors))
            print (f"URL : {res['url']}")
            print (f"Status_Code : {str(res['status'])}")
            print (f"MimeType : {res['mime']}\n")
            print (f'{choice(colors)}-----------------------------------------')
            f_r.write(res['url'] + '\n')
        except Exception as e:
            print (e)
            continue
    f_r.close()
    remove(f"{target}.json")
banner()
if len(argv) == 1:
    print ('Usages:')
    print ("""
-t domain to crawlers

Example:

# Not https:// or http:// or www.

1. ./{0} -n 1 -t hackerone.com -burp   -> index.commoncrawl.org
2. ./{0} -n 2 -t hackerone.com -burp   -> otx.alienvault.com
3. ./{0} -n 3 -t hackerone.com -burp   -> web.archieve
4. ./{0} -n All -t hackerone.com -burp -> All Of Them

""".format(argv[0]))
else:
    try:
        if "-t" in argv[1:]:
            target = argv[argv.index('-t')+1]
        if "-t" not in argv[1:]:
            exit(f"{w}[{r}!{w}] Target Not Inserted")
        if "-n" in argv[1:]:
            number = str(argv[argv.index('-n')+1])
        if "-n" not in argv[1:]:
            exit(f"{w}[{r}!{w}] Number Not Inserted")
        if number == '1':
            crawls( target )
        elif number == '2':
            otx_crawls( target )
        elif number == '3':
            web_arch( target )
        elif number == 'All':
            crawls( target )
            otx_crawls( target )
            web_arch( target )
        else :
            exit (f"{w}[{r}!{w}] Incorrect Select")
        if iden() == "Windows":
            op_w(f'https://otx.alienvault.com/indicator/domain/{target}')
        else:
            print (f"{w}[{g}+{w}] Open This Link : https://otx.alienvault.com/indicator/domain/{target}")
        del_repeat(["urls.txt" , "hostnames.txt", "Web_archieves_urls.txt", "results_crawlers.txt"])
        if "-burp" in argv[1:]:
            print (f"{w}[{g}+{w}] Pass Results to burp")
            pass_to_burp()
    except Exception as e:
        print (e)
