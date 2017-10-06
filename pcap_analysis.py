#!/usr/bin/env python2
#-*-coding:utf-8-*-

__author__='''
[Cs133]
Twitter: @133_cesium
'''
__license__='''
<+> Under the terms of the GPL v3 License.
'''

from scapy.all import *
from argparse import ArgumentParser
import StringIO
import gzip

# PCAP analysis part ====================================================================================
def get_http_headers(http_payload):
	try:
		headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]
		headers = dict(re.findall(r'(?P<name>.*?):(?P<value>.*?)\r\n', headers_raw))
	except:
		return None
	if 'Content-Type' not in headers:
		return None
	return headers

def pcap(pc, protocol):
		try:
			pcap = rdpcap(pc)
			p = pcap.sessions()
		except IOError:
			sys.exit("\033[91m[-]\033[0m IOError.")
		for session in p:
			if protocol == 'http':
				idx = flag = 0
				concat = ''
				print '\033[94m\n[ Nouvelle Session = %s ]\033[0m' % session
				for pkt in p[session]:
					if pkt.haslayer(TCP) and pkt.haslayer(Raw) and (pkt[TCP].flags == 24L or pkt[TCP].flags == 16):
						print '\033[91m\nPacket [ %d ] -------------- Nouveau Payload -------------\033[0m \n\n' % idx
						payload = pkt[TCP].payload
						load = pkt[TCP].load
						headers = get_http_headers(load)
						if headers is not None and ' gzip' in headers.values():
							print "\033[33mResponse:\033[0m",load[:15]
							for k,v in headers.iteritems():
								print k,':',v
							tab = load.split('\r\n')
							concat += tab[-1]
							flag = 1
						elif flag != 0 and headers is None:
							tab = load.split('\r\n')
							concat += tab[-1]
							try:
								sio = StringIO.StringIO(concat)
								gz = gzip.GzipFile(fileobj=sio)
								print gz.read()
								flag = 0
								concat = ''
							except:
								pass
						else:
							print payload
					idx += 1
			elif protocol == 'dns':
				#TODO
				pass

# Arguments handler part ===============================================================================
def get_args():
	args = ArgumentParser(version='0.1',description='PCAP analysis, made by Cesium133.')
	args.add_argument('-r','--rdpcap',
		action='store',
		nargs=1,
		help='Analyse un pcap [requetes HTTP par défaut].')
	args.add_argument('-p','--protocol',
		action='store',
		nargs=1,
		default=['http'],
		help='Protocole à analyser.')
	return args.parse_args()

if __name__ == '__main__':
	args = get_args()
	if args.rdpcap is not None:
		try:
			pcap(args.rdpcap[0], args.protocol[0].lower())
		except Exception as e:
			print '\033[91m[-]\033[0m Undefined error: {}'.format(e)
		sys.exit(0)
