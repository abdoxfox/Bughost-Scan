import ipcalc
import socket,random,re
import threading,configparser
import requests,sys,time,os
bg=''

G = bg+'\033[32m'
O = bg+'\033[33m'
GR = bg+'\033[37m'
R = bg+'\033[31m'


print(O+'''
\tWEBSOCKET SCANNER
\tBy : ABDOXFOX
\t  version Faster (using threading)
#'''+GR)

def cidrs():
	cidrslist =[]
	with open('ipv4.txt') as file:
		for cidr in file.readlines():
			cidrslist.append(cidr.strip('\n'))
	return cidrslist

def save(x):
	with open('wrCloudflrIp.txt','a') as fl:
		fl.write(str(x)+'\n')
		fl.close()
		
def scanner(host):
	sock=socket.socket()
	sock.settimeout(2)
	try:
		sock.connect((str(host),80))
		payload='GET / HTTP/1.1\r\nHost: {}\r\n\r\n'.format(host)
		sock.send(payload.encode())
		response=sock.recv(1024).decode('utf-8','ignore')
		for data in response.split('\r\n'):
			data=data.split(':')
			if re.match(r'HTTP/\d(\.\d)?' ,data[0]):
				print('response status : {}{}{}'.format(O,data[0],GR))
			if data[0]=='Server':
				try:
					if data[1] ==' cloudflare':
						print('{}server : {}\nFound working {}..'.format(G,host,GR))
						save(f'{host} === opened')
						payloadsnd(host)
				except Exception as e:
					print(e)
	except Exception as e:print(e)

def auto_replace(server,ip):
	packet = server.recv(1024).decode('utf-8','ignore')
	status = packet.split('\n')[0]
	if re.match(r'HTTP/\d(\.\d)? 101',status):
		print(f'{O}[TCP] response : {G}{status}{GR}')
		save(f'{ip} response ==== {status}')
	else:
		if re.match(r'HTTP/\d(\.\d)? \d\d\d ',status):
			server.send(b'HTTP/1.1 200 Connection established\r\n\r\n')
			print(f'{O}[TCP] response : {R}{status}{GR}')
			return auto_replace(server,ip)

def payloadsnd(ip):
	
	config = configparser.ConfigParser()
	config.read_file(open('configfile.ini'))
	domain = config['websocket']['custom_domain']
	port =80
	sc=socket.socket()
	sc.connect((str(ip),port))
	payload=f'GET / HTTP/1.0[crlf]Host: {domain}[crlf][crlf]'
	payload=payload.replace('[crlf]','\r\n')
	sc.send(payload.encode())
	auto_replace(sc,ip) 
	
def Main():
	ipdict={}
	ranges = cidrs()
	for k,v in enumerate(ranges):
			#clr = random.choice([G,GR,O])
			ipdict[k]=v
	iprange=[]
	for choose in range(len(ipdict)):	
		cidr=ipdict[choose]	
		for ip in ipcalc.Network(cidr):
				iprange.append(ip)
	for index in range(len(iprange)):			
		try:
			print("{}[INFO] Probing... ({}/{}) [{}]{}".format(
			R,index+1,len(iprange),iprange[index],GR))
			sc=threading.Thread(target=scanner,args=(iprange[index],))
			sc.start()
		except KeyboardInterrupt:
			print('{}Scan aborted by user!{}'.format(R,GR))
			break
						
if __name__=="__main__":
	Main()