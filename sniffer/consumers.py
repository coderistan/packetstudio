from channels.generic.websocket import WebsocketConsumer
from scapy.all import *
import json
import hashlib
import os
from packetstudio import settings as st
import time

"""
Gönderilen Mesaj Tipleri:
- packet: Paketlerin gönderildiğini bildirir
- notify: Kaç paket sonra yenileneme yapılacağını bildirir
- filtre: Filtreleme ile ilgili bilgiler gönderir(onay ve temizleme)
- info  : İstenilen paket hakkında bilgi içerir

Gelen Mesaj Tipleri:
- set : Bir ayar içeren mesajdır
- info: Bir bilgi almak isteyen mesajdır(paket hakkında)

"""

class SniffConsumer(WebsocketConsumer):
    def connect(self):
        self.filter = None
        self.paketler = []
        self.pause = False
        self.sniffer = AsyncSniffer(prn=self.send_packet)
        self.sniffer.start()        
        self.buffer = []
        self.max_packet = 50
        self.temp = 0
        self.zaman = 0
        self.sayac = 0
        self.accept()


    def send_packet(self,packet):
        if(self.pause):
            return

        if len(self.buffer) >= self.max_packet:
            # paketler gönderiliyor
            self.send(text_data=json.dumps({
                "type":"packet",
                "message":self.buffer
            }))
            self.buffer.clear()
            return

        else:
            self.add_buffer(packet)

    def add_buffer(self,packet):
        temp = time.time()

        fark = temp - self.zaman
        if(fark >= 1):
            self.max_packet = max(int(self.sayac / fark),1)
            self.sayac = 0
            self.zaman = temp

        self.sayac += 1
        self.paketler.append(packet)
        self.buffer.append(packet.summary())

    def disconnect(self, close_code):
        self.sniffer.stop()

    def check_filter(self,_filter):
        try:
            test_sniffer = sniff(filter=_filter,count=1,timeout=0.01)
            return True
        except scapy.error.Scapy_Exception:
            return False

    def reload_sniffer(self,_filter=None):
        if self.sniffer.running:
            self.sniffer.stop()

        self.sniffer = AsyncSniffer(filter=_filter,prn=self.send_packet)
        self.sniffer.start()
        self.filter = _filter
        self.buffer.clear()

    # mesaj alınırsa
    def receive(self, text_data):
        try:
            message = json.loads(text_data)
            _type = message['type']

            # ayarlama işlemleri
            if(_type == "set"):
                
                # temizleme
                if message["data"] == "clear": 
                    if self.filter == None:
                        result = "Uygulanmış bir filtre yok"
                    else:
                        self.reload_sniffer()
                        result = "Filtre temizlendi"

                    self.send(text_data = json.dumps({"type":"filter","info":result}))

                # duraklatma/devam etme
                elif message["data"] == "play":
                    # Paket yakalayıcıyı duraklat/devam ettir
                    self.pause = not self.pause

                    self.send(text_data=json.dumps({
                        "type":"notify",
                        "info":"Paket yakalama {}".format("durduruldu" if self.pause else "devam ediyor")
                    }))
                           
                # paketleri kaydetme
                elif message["data"] == "save":
                    # kaydetme işlemi
                    # kullanıcı özelinde kayıt işlemi
                    result = self.sniffer.stop()
                    name = hashlib.md5(result[0].show(dump=True).encode("utf-8")).hexdigest()+".cap"
                    if(not os.path.exists(os.path.join(st.BASE_DIR,"sniffer","download"))):
                        os.mkdir(os.path.join(st.BASE_DIR,"sniffer","download"))
                    path = os.path.join(st.BASE_DIR,"sniffer","download",name)
                    wrpcap(path,result)
                    self.send(text_data=json.dumps(
                        {"type":"save",
                        "info":name}
                    ))

                # filtre uygulama
                else:
                    filter_string = message["data"]
                    
                    # eğer bir önceki filtre ile aynı filtre uygulanacaksa pas geçilir
                    if filter_string.strip() == self.filter:
                        print("Aynı filtre. Pas geçiliyor: ",filter_string)
                        return

                    if self.check_filter(filter_string):
                        self.reload_sniffer(filter_string)
                        result = "Filtre uygulandı: "+filter_string
                        
                    else:
                        filter_string = None
                        result = "Hatalı filtre. Girdinizi tekrar kontrol edin"

                    self.send(text_data = json.dumps(
                        {"type":"filter","info":result,"value":filter_string}
                    ))

            # paket hakkında bilgi alma
            elif _type == "info":
                
                # toplanan 
                self.send(text_data = json.dumps(
                    {"type":"info",
                    "message":self.paketler[message["index"]].show(dump=True)}
                ))

        except Exception as e:
            self.reload_sniffer(self.filter)

    def sendWrap(self,data):
        self.send(text_data=json.dumps(
            data
        ))