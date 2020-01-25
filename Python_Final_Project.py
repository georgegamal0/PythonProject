import socket
import subprocess
import sys , os
from datetime import datetime
import time
import logging
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler
from bs4 import BeautifulSoup
import requests
import re
from bs4 import Comment
import iptc
import scapy
from scapy.all import *



def monitor():
    print("This will monitor directory called \"Done\" ")
    logging.basicConfig(level=logging.INFO,
            format='%(asctime)s - %(message)s',
				datefmt='%Y-%m-%d %H:%M:%S')
    path = sys.argv[1] if len(sys.argv) > 1 else '.'
    event_handler = LoggingEventHandler()
    observer = Observer()
    observer.schedule(event_handler, 'Done', recursive=True)
    observer.start()
    try:
    	while True:
    		time.sleep(1)
    except KeyboardInterrupt:
    	observer.stop()
    observer.join()

def spliter():
    file = open('logs.txt','r')
    textf = file.readlines()
    logs = []
    for i in textf:
    	logs.append(i.split())

    for ips in logs:
	    print 

    for uAgent in logs:
    	print("IP is: "+ uAgent[0] +  " using method: " + uAgent[5][1:] + " to access URI of: " + uAgent[6][1:-1]+" with user agent name of: " + (' '.join(uAgent[11:-1]))[1:-1]  )


def portScan(iplist):
    try:
        subprocess.call('clear', shell=True)
        tcp_or_udp = input("For UDP scan press 1 (TCP default) ")
        udp ='0'

        if(tcp_or_udp == '1'):
            udp ='1'
            print("UDP selected")
        else:
            print("TCP selected")

        
        print("="*30)
        print(iplist)
        openPorts = []
        allData={}
        for ip in iplist:
            allData[ip] = []
            print("For ip: "+str(ip))
            for port in range(1,1023):
                real = ip.encode('utf-8')
                targetIP = socket.gethostbyname(real)
                if (udp == '1'):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((targetIP, port))
                if result == 0:
                    openPortNMAP = "Port Open "+format(port)+"\n"+(os.popen('nmap -sC -sV -p '+str(port)+" "+str(ip)).readlines())[5]
                    allData[ip].append(openPortNMAP)
                    print (openPortNMAP)
                    #openPorts.append(openPortNMAP)
                sock.close()

    except KeyboardInterrupt:
        print ("\nYou pressed Ctrl+C..\nGood bye!")
        sys.exit()

    except socket.gaierror:
        print ('Hostname could not be resolved. Exiting')
        sys.exit()

    except socket.error:
        print( "Couldn't connect to server")
        sys.exit()
    if openPorts==[]:
        print("There is no open ports")
    else:
        port_str = ""
        for i in openPorts:
            port_str += "," + str(i)
        if (port_str[-1]==','):
            port_str = port_str[:-1]
        if (port_str[0]==","):
            port_str = port_str[1:]
        #openPortNMAP = os.popen('nmap -sC -sV -p '+port_str+" "+ target).readlines()
    return allData


def ipRange():
	inputIP1 = input("Enter first ip: ")
	inputIP2 = input("Enter last ip: ")
	return inputIP1,inputIP2

def scanner(inputIP1,inputIP2):
	res = os.popen('arp-scan '+inputIP1+"-"+inputIP2).readlines()
	for i in range(2,len(res)):
		if res[i]=="\n":
			break
		else:
			IPs.append((res[i].split("\t"))[0])
	return IPs

def webPageParser():
    fullURL = input("Enter target website (ex: \"http(s)://www.example.com\"): ")
    resp = requests.get(fullURL)
    soup = BeautifulSoup(resp.text , "lxml")
    domain = fullURL.split("www")[1]
    print ("Domain:\n",domain,"\n\n")



    aTagForURL = soup.find_all('a')
    tags = []
    for tag in soup.find_all(True):
        if tag.name not in tags:
            tags.append(tag.name)
    print("All tags:\n",tags,"\n\n")


    Fullurls = []
    subDomains = []
    for tag in aTagForURL:
        url = tag.get('href')
        subDomain = tag.get('href')
        url = re.findall("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+",url)
        subDomain = (re.findall("https?:\/\/[a-zA-Z.]*",subDomain))
        if  url not in Fullurls:
            Fullurls.append(url)
        if  subDomain not in subDomains:
            subDomains.append(subDomain)
    print("All URLs:\n",Fullurls,"\n\n")
    print("ALL subdomains:\n",subDomains,"\n\n")


    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    comment = []
    for c in comments:
        if c != "":
            comment.append(c)
    if comment != []:
        print (comment)
    else:
        print("No comments found")




#Port Monitor

def Open(port):
    os.system("nc -nvlp " + str(port) + " &")

def UOP():
    global myIP
    host = socket.gethostbyname(myIP)
    openPorts = []
    for port in range(1, 20000):
        if port not in wellknown and port < 20000:
            scannerTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.1)
            status = scannerTCP.connect_ex((host, port))
            if not status:
                openPorts.append(port) 
    for p in openPorts:
        os.system("nc -nvlp " + str(p) + " &")
    return openPorts

def blockIP(ip):
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    rule = iptc.Rule()
    rule.in_interface = "eth0"
    target = iptc.Target(rule, "DROP")
    rule.target = target
    rule.src = ip  
    chain.insert_rule(rule)

    os.system("iptables -A OUTPUT -d " + "" + ip + " " + "-j DROP") 

def print_summary(pkt):
    global myIP
    global unKnown
    tcp_sport = ""

    if 'TCP' in pkt:
        tcp_sport=pkt['TCP'].sport

    if (pkt['IP'].src == myIP)  and tcp_sport in unKnown:
        blockIP(pkt['IP'].dst)
        Open(tcp_sport)
        print("Attack detected!")
        print("Blocking " + pkt['IP'].dst + " ...\nBlocked!\n")


def Monitor():
    sniff(filter="ip",prn=print_summary)
    sniff(filter="ip and host " + myIP, prn=print_summary)


wellknown = [1, 5, 7, 18, 20, 21, 22, 23, 25, 29, 37, 42, 43, 49, 53,
69, 70, 79, 80, 103, 108, 109, 110, 115, 118, 119, 137, 139, 143,
150, 156, 161, 179, 190, 194, 197, 389, 396, 443, 444, 445, 458, 546, 547, 563, 569, 1080]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("8.8.8.8", 80))
myIP = s.getsockname()[0]
s.close()
unKnown = UOP()
subprocess.call('clear', shell=True)

while True:
    userSel = input("*"*50+"\nEnter \n\"1\" for parsing log file named: logs.txt\n\"2\" for directory monitoring\n\"3\" for scanning network\n\"4\" for monitoring attacks\n\"5\" for parsing web page\n\"6\" to exit\n")
    if int(userSel) == 1:
        spliter()
    elif int(userSel) == 2:
        monitor()
    elif int(userSel) == 3:
        firstIP , lastIP = ipRange()
        IPs = []
        IPs = scanner(firstIP,lastIP)
        data = {}
        data =  portScan(IPs)
        if(len(data) == 0):
            print("not ports were found ")
        else:
            print(data)
    elif int(userSel) == 4:
        if __name__ == "__main__":
            if(len(unKnown)):
                print("My ip is " + myIP + "....")
                Monitor()
            else:
                print("No ports were detected")
    elif int(userSel) == 5:
        webPageParser()
    elif int(userSel) == 6:
        subprocess.call('clear', shell=True)
        break