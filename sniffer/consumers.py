from channels.generic.websocket import WebsocketConsumer
from scapy.all import *
import json
import hashlib
import os
from packetstudio import settings
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
class Message:
    def __init__(self,data):
        self.type = data["type"]
        self.do = data["do"]
        self.data = data.get("data",None)

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
        self.message = None
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
        if self.sniffer.running:
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

        self.sniffer = AsyncSniffer(filter=self.filter,prn=self.send_packet)
        self.sniffer.start()
        self.buffer.clear()

    def clear_filters(self):
        if self.filter == None:
            result = "Uygulanmış bir filtre yok"
        else:
            self.reload_sniffer()
            result = "Filtre temizlendi"

        return {"type":"filter","info":result}

    def play_or_pause(self):
        # Paket yakalayıcıyı duraklat/devam ettir
        self.pause = not self.pause
        return {
            "type":"notify",
            "info":"Paket yakalama {}"\
                .format("durduruldu" if self.pause else "devam ediyor")
            }

    def save_packets(self):
        # kaydetme işlemi
        # kullanıcı özelinde kayıt işlemi
        try:
            result = self.sniffer.stop()
            name = hashlib.md5(result[0]\
                .show(dump=True)\
                .encode("utf-8"))\
                .hexdigest()+".cap"
            
            if(not os.path.exists(os.path.join(settings.BASE_DIR,"sniffer","download"))):
                os.mkdir(os.path.join(settings.BASE_DIR,"sniffer","download"))
            
            path = os.path.join(settings.BASE_DIR,"sniffer","download",name)
            wrpcap(path,result)

            result = name
        except Exception as e:
            # TODO: doğru hata yakalaması yapılmalı
            result = None

        # TODO: paket kaydedilmesi hatalı olursa?
        return {"type":"save","info":result}

    def do_filter(self):
        filter_string = self.message.data
        
        # eğer bir önceki filtre ile aynı filtre uygulanacaksa pas geçilir
        if filter_string.strip() == self.filter:
            # TODO: Pas geçme işlemi kullanıcıya bildirilmeli
            print("Aynı filtre. Pas geçiliyor: ",filter_string)
            return

        if self.check_filter(filter_string):
            self.filter = filter_string
            self.reload_sniffer()
            result = "Filtre uygulandı: "+filter_string
            
        else:
            filter_string = None
            result = "Hatalı filtre. Girdinizi tekrar kontrol edin"

        return {"type":"filter","info":result,"value":filter_string}

    def get_packet_info(self):
        result = self.paketler[self.message.data].show(dump=True)
        return {"type":"info","message":result}

    def invalid(self):
        # geçersiz işlemler için
        return {"type":"notify","info":"Geçersiz bir işlem"}

    def get_work(self):
        # TODO: else: pass durumları düzenlenmeli

        if self.message.type == "set":
            if self.message.do == "clear":
                return self.clear_filters
            elif self.message.do == "play":
                return self.play_or_pause
            elif self.message.do == "save":
                return self.save_packets
            elif self.message.do == "filter":
                return self.do_filter

        elif self.message.type == "info":
            if self.message.do == "packet_info":
                return self.get_packet_info
        
        return self.invalid


    # mesaj alınırsa
    def receive(self, text_data):
        data = json.loads(text_data)
        self.message = Message(data)

        # mesaj tipine göre yapılacak iş
        work = self.get_work()

        # işi gerçekleştirme
        result = work()
        
        # sonuçları gönderme
        self.sendWrap(result)

    def sendWrap(self,data):
        self.send(text_data=json.dumps(
            data
        ))