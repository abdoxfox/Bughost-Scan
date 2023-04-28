import ipcalc
import threading
import sys
import argparse,queue
import requests
import time

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
		self.queue = queue.Queue()
		self.request = requests.get
		self.thread = threading.Thread
		self.total =1
		self.progress = 1
	
	def fetchqueue(self):
		while True:
			ip = str(self.queue.get())
			sys.stdout.write(f'scaning...{ip} ==> progressing....  ({self.progress}/{self.total})\r')
			sys.stdout.flush()
			self.Sendrequest(ip)
		self.queue.task_done()
				
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
			response = f'\n{G}{ip}\t{status}\t{server}{GR}\r\n'
			sys.stdout.write(response)
			sys.stdout.flush()
			if self.output :
				with open(self.output,'a') as file:
					file.write(response)
					file.close()
				
		except Exception as e:
			pass
		self.progress  += 1
	
	def main(self):
		sys.stdout.write(f'{O}Coverting ip_ranges to single IPs ...\r')
		sys.stdout.flush()	
		cidrs = open('ipv4.txt','r').read().split()
		for every in cidrs:	
		    for ip in ipcalc.Network(every):
		    	self.queue.put(ip)
		    	self.total += 1
		sys.stdout.write(f'{O}Done √ Scaning starts {GR}\r')
		sys.stdout.flush()
		time.sleep(2)
		self.threadsrun()
		
	def threadsrun(self):
		for _ in range(self.threads):
				thread = self.thread(target=self.fetchqueue)
				thread.start()
		self.queue.join()

		
def parseargs():
		parser = argparse.ArgumentParser(
			formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=52))
		parser.add_argument('-t','--threads',help='num of threads',dest='threads',type=int,default=10)
		parser.add_argument('-p','--port',help='port to scan',dest='port',type=int,default=80)
		parser.add_argument('-P','--proxy',help='proxy ip:port ex: 12.34.56.6:80',dest='proxy',type=str)
		parser.add_argument('-o','--output',help='save output in file',dest='output',type=str)
	
		args = parser.parse_args()		
		if args.help:
			parser.print_help()
			
			return
		cdnscan=cdnscanner()
		cdnscan.threads = args.threads
		cdnscan.port = args.port
		cdnscan.proxy = args.proxy
		cdnscan.output = args.output
		
		cdnscan.main()
		
if __name__ =='__main__':	
	parseargs()
