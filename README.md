Yerel bilgisayarınızdaki paketleri dinlemek için kullanabileceğiniz django arayüzü. Scapy yardımı ile geliştirilmiştir. WebSocket kullanarak iletişim gerçekleştirilmiştir. 

Projenin çalıştırılabilmesi için öncelikle gereklililerin yüklenmesi gereklidir. Proje Python3.7 sürümü ve üstünde çalışır. Gereklilikleri yüklemek için proje klasöründe

python3.7 -m pip install -r requirements.txt

komutu çalıştırılmalıdır. Gereklilikler yüklendikten projeyi ilklendirmek için

python3.7 manage.py migrate

komutu girilmelidir. İlk işlemler tamamlandıktan sonra proje klasöründe sudo komutu ile birlikte

sudo python3.7 manage.py runserver

komutu çalıştırılırsa proje 127.0.0.1:8000 adresi üzerinden yayın yapmaya başlayacaktır.

![PacketStudio önizleme](https://raw.githubusercontent.com/coderistan/packetstudio/master/static/img/preview.png?token=AGXU4OM35NLIC2FB6NA6H7C7GT4SI)