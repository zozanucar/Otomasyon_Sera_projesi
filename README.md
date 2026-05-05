<img width="1600" height="1204" alt="image" src="https://github.com/user-attachments/assets/6fac91fb-7189-4746-8adc-4fd07554ef58" />
# 🌿 Akıllı Sera Otomasyonu (Otomasyon_Sera_projesi)

Bu proje, **ZEE** ekibi tarafından geliştirilmiş kapsamlı bir sera otomasyon sistemidir. Projenin temel amacı, sera içerisindeki çevresel faktörleri otonom olarak izlemek ve bitki gelişimi için en ideal koşulları sağlamaktır.

## 🚀 Proje Özellikleri
* **Otomatik İklimlendirme:** İçerideki sıcaklık ve nem durumuna göre havalandırma sisteminin devreye girmesi.
* **Akıllı Sulama:** Toprak nem sensörlerinden alınan verilere göre su pompalarının otonom kontrolü.
* **Veri Takibi:** Sensörlerden gelen veriler doğrudan kullanılmaz, kendi yazdığımız algoritmalarla hesaplanarak işlenir. Bu sayede sistem, örneğin sıcaklığın düşeceğini önceden tahmin edip tehlike anından önce alarm verir. Yani sistemimiz sadece olaylara tepki vermez, olayları önceden öngörüp koruma sağlar.

## 🛠️ Kullanılan Teknolojiler

**Donanım:**
* STM32F4 Discovery (veya projede kullandığın diğer mikrodenetleyiciler)
* Toprak Nem Sensörü, DHT11/DHT22 Sıcaklık Sensörü vb.
* Motor sürücüler ve su pompası

**Yazılım:**
* C / C++ 
* STM32CubeIDE / Arduino IDE
* Python (Eğer veri analizi veya arayüz varsa)

## ⚙️ Kurulum ve Çalıştırma
Projeyi kendi bilgisayarınızda çalıştırmak için:
1. Bu repoyu klonlayın: `git clone https://github.com/zozanucar/Otomasyon_Sera_projesi.git`
2. Gerekli kütüphaneleri yükleyin.
3. Kodları mikrodenetleyiciye yüklemek için STM32CubeIDE (veya kullandığın program) üzerinden derleyip flashlayın.
