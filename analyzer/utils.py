from scapy.all import *

class Oturum(object):
	def __init__(self,oturum_adi,paket_listesi):
		self.name = oturum_adi
		self.paketler = paket_listesi
		
		if IP in self.paketler[0]:
			self.first = self.paketler[0].getlayer(IP).src
			self.second = self.paketler[0].getlayer(IP).dst
		else:
			self.first = self.paketler[0].src
			self.second = self.paketler[0].dst

	def ip_listesi(self):
		return [i.summary() for i in self.paketler]

class PcapAnalyzer(object):
	def __init__(self,file_name):
		self.file_name = file_name
		self.paketler = None

	def is_pcap(self):
		try:
			self.paketler = rdpcap(self.file_name)
			self.paketler.stats.append(IPv6)
			return True
		except Exception as e:
			return False

	def get_protocols_data(self):
		t = len(self.paketler.getlayer(TCP))
		u = len(self.paketler.getlayer(UDP))
		i = len(self.paketler.getlayer(ICMP))
		v = len(self.paketler.getlayer(IPv6))
		
		return {
			"max":len(self.paketler),
			"tcp":t,
			"udp":u,
			"icmp":i,
			"ipv6":v,
			"unk":len(self.paketler) - (t+u+i),
		}

	def get_ip_data(self):
		# IP adresleri ile ilgili veriler
		# TCP oturumları
		oturumlar = self.paketler.sessions()
		return {"sessions":[Oturum(i,oturumlar[i]) for i in oturumlar]}
		