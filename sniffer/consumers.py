from channels.generic.websocket import WebsocketConsumer
from scapy.all import *
import json

class SniffConsumer(WebsocketConsumer):
    def connect(self):
        self.sniffer = AsyncSniffer(prn=self.send_packet)
        self.sniffer.start()        
        self.accept()

    def send_packet(self,packet):
        if TCP in packet:
            self.send(text_data=json.dumps({
                "message":packet.summary()
            }))

    def disconnect(self, close_code):
        self.sniffer.stop()
        pass

    # mesaj alınırsa
    def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json['message']
#        self.send(text_data=json.dumps({
#            'message': message
#        }))