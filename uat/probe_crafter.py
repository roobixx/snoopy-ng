#!/usr/bin/python
# Sources:
#  https://docs.python.org/2/library/threading.html
#  http://blog.packetheader.net/2014/01/sending-80211-packets-with-scapy.html
#  https://www.centos.org/docs/5/html/5.2/Virtualization/sect-Virtualization-Tips_and_tricks-Generating_a_new_unique_MAC_address.html
#  http://stackoverflow.com/questions/22700174/multi-threading-in-scapy-for-sending-packet
#  http://static.usenix.org/legacy/events/sec06/tech/full_papers/franklin/franklin_html/
#  https://hal.inria.fr/hal-00859013/PDF/IntershipReport_Levent_DEMIR.pdf
#  https://meraki.cisco.com/lib/pdf/meraki_whitepaper_cmx.pdf

import sys
import os
import time
import random
import logging
import threading
import json
import datetime

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

LOG_LEVEL = logging.INFO
LOG_FORMAT = '%(asctime)s %(levelname)s %(filename)s: %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

logging.basicConfig(level=LOG_LEVEL, format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
log = logging.getLogger('')

""""""
START = datetime.datetime.now()
DEVICES = {}
CHANNELS = range(1, 13)
CHANNEL = 0

# os.system('iw dev mon0 set channel %d' % CHANNEL)

""""""
def channel_hop(iface='mon0'):
	global CHANNEL
	try:
		CHANNEL = CHANNEL + 1
		if CHANNEL > 13:
			CHANNEL = 1
		log.info('[*] Hopping to channel [%d]' % (CHANNEL))
		os.system("iwconfig %s channel %d" % (iface, CHANNEL))
	except:
		raise

""""""
def randomMAC():
	mac = [ 0xf8, 0xd1, 0x11,
		random.randint(0x00, 0x7f),
		random.randint(0x00, 0xff),
		random.randint(0x00, 0xff) ]
	return ':'.join(map(lambda x: "%02x" % x, mac))

class ProbeCrafter():
	""""""
	def __init__(self,ssid='test',bssid='00:11:22:33:44:55',mode=1,hop=False):

		self.rates   = "\x03\x12\x96\x18\x24\x30\x48\x60"
		self.ssid    = ssid
		self.source  = self.get_mac()
		self.bssid   = bssid
		self.mode    = mode
		self.hop     = hop
		self.inter   = 0.1

		log.info('[*] Initialized new device [%s]' % (self.source))

	""""""
	def get_mac(self):
		global DEVICES
		while True:
			mac = randomMAC()
			if not DEVICES.has_key(mac):
				DEVICES[mac] = { 'probes': 0 }
				return mac

	""""""
	def run(self):
		if self.mode == 1 or mode == 2:
			self.run_active_mode()

	""""""
	def run_active_mode(self):
		for x in range(1, 160):
			self.probe_request(count=self.get_bursts())
			if self.hop:
				channel_hop()
			time.sleep(10)
		while True:
			self.probe_request(count=self.get_bursts())
			if self.hop:
				channel_hop()
			time.sleep(50)

	""""""
	def get_bursts(self):
		return random.randint(5,10)

	""""""
	def probe_request(self,count=10,ssid='',dst='ff:ff:ff:ff:ff:ff'):
		global DEVICES

		if not ssid:
			ssid=self.ssid

		param = Dot11ProbeReq()
		essid = Dot11Elt(ID='SSID',info=ssid)
		rates  = Dot11Elt(ID='Rates',info=self.rates)
		dsset = Dot11Elt(ID='DSset',info='\x01')
		pkt = RadioTap()\
			/Dot11(type=0,subtype=4,addr1=dst,addr2=self.source,addr3=self.bssid)\
			/param/essid/rates/dsset

		log.info('[*] Sending probes: src=[%s], count=%d' % (self.source,count))
		try:
			sendp(pkt, count=count, inter=self.inter, verbose=0)
			DEVICES[self.source]['probes'] += count
		except:
			raise

""""""
def end_program():
	log.info('[-] Terminating probes generator...')

	global START
	end = datetime.datetime.now()
	duration = end - START

	result = {
		'start': str(START),
		'end': str(end),
		'duration': str(duration),
		'probes': 0,
		'devices': DEVICES
	}

	for d in DEVICES:
		result['probes'] += DEVICES[d]['probes']

	print ""
	print json.dumps(result, indent=4)

""""""
def thread_worker(mode,hop):
	crafter = ProbeCrafter(mode=mode,hop=hop)
	crafter.run()

# main routine
if __name__ == "__main__":
	if len(sys.argv) > 1:
		mode = int(sys.argv[1])
	else:
		mode = 1

	conf.iface = 'mon0'

	log.info('[+] Starting probes generator...')
	channel_hop()

	try:

		if mode == 1 or mode == 2:
			t = threading.Thread(target=thread_worker, args=(mode,mode==2))
			t.daemon = True
			t.start()
		elif mode == 3:
			threads = []
			for x in range(0, 10):
				t = threading.Thread(target=thread_worker, args=(1,False))
				time.sleep(random.uniform(0.5,5))
				t.daemon = True
				t.start()
				threads.append(t)

		while True:
			time.sleep(1)
	except (KeyboardInterrupt, SystemExit):
		end_program()
		exit(0)

end_program()

