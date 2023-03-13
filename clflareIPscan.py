import ipcalc
import socket,random
import threading
import sys
import argparse,queue
import requests

bg=''

G = bg+'\033[32m'
O = bg+'\033[33m'
GR = bg+'\033[37m'
R = bg+'\033[31m'


print(O+'''
\tWEBSOCKET SCANNER
\tBy : ABDOXFOX
\tUpdate 13/03/2022
'''+GR)
class cdnscanner:
	def __init__(self):
		self.queuelst = queue.Queue()
		self.request = requests.get
		self.thread = threading.Thread
	
	
	def fetchqueue(self):
		self.progress = 1
		while True:
			ip = str(self.queuelst.get())
			sys.stdout.write(f'scaning...{ip} ==> progressing....  ({self.progress}/{self.len_ips})\r')
			sys.stdout.flush()
			self.Sendrequest(ip)
		self.queuelst.task_done()
		
	
	def Sendrequest(self, ip):
		url = (f'https://{ip}' if self.port == 443 else f'http://{ip}:{self.port}')
		try:
			if self.proxy:
				proxyhost,port = self.proxy.split(':')[0],int(self.proxy.split(':')[1])
				proxy = {'http' : f'http://{proxyhost}:{port}', 'https' : 'http://{proxyhost}:{port}'}
				req = self.request(url,proxy,timeout=7,allow_redirects=False)
			
			else:
				req = self.request(url,timeout=7,allow_redirects=False)
			status = req.status_code
			server = req.headers['server']
			sys.stdout.write(f'{G}{ip}\t{status}\t{server}{GR}\n')
			
			
		except Exception as e:
			pass
		self.progress  += 1
	
	def main(self):
		
		cidrs = open('ipv4.txt','r').read().split()
		self.all_ips=[]
		for every in cidrs:	
			for ip in ipcalc.Network(every):
					self.all_ips.append(ip)
		
		for ip in self.all_ips:
			self.queuelst.put(ip)
		self.len_ips = len(self.all_ips)
		self.threadsrun()
		
	def threadsrun(self):
		for _ in range(self.threads):
				thread = self.thread(target=self.fetchqueue)
				thread.start()
		self.queuelst.join()

		
def parseargs():
		parser = argparse.ArgumentParser(
			formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=52))
		parser.add_argument('-t','--threads',help='num of threads',dest='threads',type=int,default=10)
		parser.add_argument('-p','--port',help='port to scan',dest='port',type=int,default=80)
		parser.add_argument('-P','--proxy',help='proxy ip:port ex: 12.34.56.6:80',dest='proxy',type=str)
		
	
		args = parser.parse_args()
		
		if len(sys.argv) <= 1:
			parser.print_help()
			
			return
		cdnscan=cdnscanner()
		cdnscan.threads = args.threads
		cdnscan.port = args.port
		cdnscan.proxy = args.proxy
		
		cdnscan.main()
		
		
parseargs()