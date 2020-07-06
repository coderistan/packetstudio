Projenin çalıştırılabilmesi için öncelikle gereklililerin yüklenmesi gereklidir. Proje Python3.7 sürümü ve üstünde çalışır. Gereklilikleri yüklemek için proje klasöründe

python3.7 -m pip install -r requirements.txt

komutu çalıştırılmalıdır. Gereklilikler yüklendikten projeyi ilklendirmek için

python3.7 manage.py migrate

komutu girilmelidir. İlk işlemler tamamlandıktan sonra proje klasöründe sudo komutu ile birlikte

sudo python3.7 manage.py runserver

komutu çalıştırılırsa proje 127.0.0.1:8000 adresi üzerinden yayın yapmaya başlayacaktır.