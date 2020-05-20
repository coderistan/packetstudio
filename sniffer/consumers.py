from channels.generic.websocket import WebsocketConsumer
from scapy.all import *
import json

class SniffConsumer(WebsocketConsumer):
    def connect(self):
        self.filter_list = []
        self.allow = {
            "tcp":TCP,
            "arp":ARP,
            "udp":UDP,
            "icmp":ICMP,
            "dns":DNS,
        }
        self.sniffer = AsyncSniffer(prn=self.send_packet)
        self.sniffer.start()        
        self.buffer = []
        self.max_packet = 15
        self.accept()
        

    def send_packet(self,packet):
        if len(self.buffer) == self.max_packet:
            self.send(text_data=json.dumps({
                "message":self.buffer
            }))
            self.buffer.clear()
        elif len(self.filter_list):
            for i in self.filter_list:
                if i in packet:
                    self.buffer.append(packet.summary())
        else:
            self.buffer.append(packet.summary())

    def disconnect(self, close_code):
        self.sniffer.stop()
        pass

    # mesaj alınırsa
    def receive(self, text_data):
        try:
            text_data_json = json.loads(text_data)
            message = text_data_json['filtre']
            if(message == "clear"):
                self.filter_list.clear()
                return

            f = message.split(",")
            for i in f:
                if i.lower() not in self.allow:
                    return
            
            self.filter_list.clear()
            for i in f:
                print("Filtre eklendi: {}".format(i))
                self.filter_list.append(self.allow.get(i.lower()))
        except Exception as e:
            pass
#        self.send(text_data=json.dumps({
#            'message': message
#        }))