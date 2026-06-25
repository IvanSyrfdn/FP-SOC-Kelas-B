# Laporan Final Project SOC Kelas B

**Mata Kuliah:** Security Operations Center
**Kelompok:** 1 (Satu)
**Program Studi:** Teknologi Informasi, Institut Teknologi Sepuluh Nopember

## Anggota Kelompok
| Nama | NRP |
| :--- | :--- |
| Moch Rizki Nasrullah        | 5027241038 |
| Ivan Syarifuddin           | 5027241045 |
| Theodorus Aaron Ugraha      | 5027241056 |
| Ananda Fitri Wibowo         | 5027241057 |
| M. Alfaeran Auriga Ruswandi | 5027241115 |

## Pendahuluan
Proyek ini merupakan implementasi lingkungan pemantauan keamanan jaringan secara *real-time* yang difokuskan pada deteksi ancaman multi-vektor dan penyaringan peringatan keamanan (*alert fatigue mitigation*). Tidak hanya mengandalkan *ruleset* statis,  proyek SOC ini diintegrasikan dengan model *Artificial Intelligence* (AI) Qwen 2B untuk melakukan klasifikasi log lanjutan. Pendekatan ini memungkinkan sistem untuk membedakan antara ancaman nyata dan *false alarm* (positif palsu) secara otomatis.

## Infrastruktur Sistem
Lingkungan operasi dibangun menggunakan layanan *cloud* Digital Ocean yang terbagi menjadi tiga *Virtual Machine* (VM). Arsitektur ini dirancang terpisah (*decoupled*) antara pusat analitik dan *endpoint* pelaksana.

| Hostname | Alamat IP | Peran |
| :--- | :--- | :--- |
| **Manager** | `206.189.159.153` | SOC Center & AI Analyzer |
| **Agent-1** | `188.166.238.147` | Managed Endpoint 1 |
| **Agent-2** | `152.42.253.175` | Managed Endpoint 2 |

## Layanan Deteksi
Sistem ini secara aktif memantau dan menangani lima kategori ancaman atau layanan keamanan pada jaringan:
1. **Detection IDS Suricata:** Pemantauan anomali lalu lintas jaringan berbasis *signature*, mendeteksi aktivitas seperti pemindaian (*scanning*) atau protokol anomali (ICMP ping).
2. **Malware:** Pendeteksian berkas berbahaya pada sistem yang mencakup respons aktif (*active response*) untuk mengeksekusi skrip penanganan (misalnya `remove-threat.sh`).
3. **Shellshock:** Pemantauan terhadap upaya eksploitasi kerentanan eksekusi kode arbitrer pada layanan *web* (CVE-2014-6271).
4. **SQL Injection:** Deteksi aktivitas injeksi *query* berbahaya yang menargetkan kerentanan pada layanan basis data.
5. **Phishing:** Identifikasi upaya manipulasi psikologis berbasis *email* menggunakan *automated scanner*.

## Integrasi AI (Qwen 2B) & Klasifikasi *False Alarm*
Dalam lingkungan SOC, volume peringatan yang terlalu banyak dapat membebani analis keamanan. Oleh karena itu, seluruh peringatan diekspor ke dalam format JSON untuk dilatih dan dievaluasi oleh AI **Qwen 2B** yang bertindak sebagai modul `soc_classifier`. 

Klasifikasi ancaman ditentukan melalui ambang batas (*threshold*) tingkat keparahan (*rule_level*):
* **Level ≤ 4 (Auto-Suppressed):** Sistem menganggap *alert* tersebut tidak memiliki risiko yang memadai dan langsung melabelinya sebagai `FALSE_ALARM`.
* **Level ≥ 5 (AI Analyzed):** *Alert* diteruskan ke model Qwen 2B untuk dianalisis lebih dalam. Model akan mengevaluasi *log context* (seperti IP asal, waktu kejadian, eskalasi hak istimewa, pergerakan lateral, dll.) sebelum memberikan *verdict* akhir.

### Analisis Klasifikasi pada Layanan

Berikut adalah hasil evaluasi sistem dan AI Qwen 2B terhadap 5 layanan keamanan yang diimplementasikan:

**1. Detection IDS Suricata**
<img width="1430" height="388" alt="IDS-Suricata" src="https://github.com/user-attachments/assets/4812dedb-d91e-476e-b9f1-0cbebe4177d7" />
> **Penjelasan:** Log menunjukkan adanya aktivitas ping (`Suricata: Alert - GPL ICMP_INFO PING *NIX`) dengan Rule ID `86601`. Karena tingkat peringatan ini tergolong sangat rendah (`rule_level: 3`), sistem tidak perlu melibatkan AI. Modul `soc_classifier` secara otomatis meredam log ini (`Rule level below threshold (< 4), auto-suppressed`) dan melabelinya sebagai `FALSE_ALARM`.

**2. Malware**
<img width="1470" height="390" alt="Malware-Removed" src="https://github.com/user-attachments/assets/67888132-c5d6-4869-93a5-7dbdf8c6de3f" />
> **Penjelasan:** Gambar di atas menunjukkan log dari tindakan sistem (`Active response: active-response/bin/remove-threat.sh - add`) dengan Rule ID `657`. Karena ini merupakan pencatatan aksi respons rutin dan hanya memiliki `rule_level: 3`, sistem langsung mengklasifikasikannya sebagai `auto-suppressed` dengan *verdict* `FALSE_ALARM` tanpa perlu analisis AI lebih lanjut.

**3. Shellshock**
<img width="1482" height="407" alt="ShellShock" src="https://github.com/user-attachments/assets/05f7bb6e-5660-4902-bce9-371603fc2253" />
> **Penjelasan:** Terdapat peringatan tingkat kritis (`rule_level: 15`) dengan deskripsi `Shellshock attack detected` (Rule ID `31168`). Karena levelnya di atas 4, AI Qwen 2B ditugaskan untuk menganalisis konteks log. AI menyimpulkan *verdict* `FALSE_ALARM` karena tidak menemukan indikator berbahaya lanjutan pada sistem, seperti IP asal yang mencurigakan, aktivitas di luar jam kerja, eskalasi hak istimewa, pergerakan lateral, maupun indikasi eksfiltrasi data.

**4. SQL Injection**
<img width="1487" height="412" alt="SQL-Injection" src="https://github.com/user-attachments/assets/466b3933-2943-46bc-85f7-b4a599ddebf4" />
> **Penjelasan:** Log mencatat `SQL injection attempt.` (Rule ID `31103`) dengan tingkat keparahan menengah (`rule_level: 7`). AI menganalisis konteks serangan ini dan memberikan *reasoning* bahwa tidak terdapat jejak anomali lebih lanjut (seperti keberhasilan injeksi, eksfiltrasi data, atau eskalasi hak istimewa pengguna). Oleh karena itu, AI secara cerdas menyaring peringatan ini sebagai `FALSE_ALARM`.

**5. Phishing**
<img width="1461" height="527" alt="Phising-Alerts" src="https://github.com/user-attachments/assets/14e7bcaa-a18e-4990-b668-b0219dda37ee" />
> **Penjelasan:** Peringatan `Phishing email detected by automated scanner.` (Rule ID `100207`) memiliki tingkat keparahan tinggi (`rule_level: 12`). Meski memicu alert tinggi, evaluasi AI Qwen 2B menyatakan bahwa ini adalah `FALSE_ALARM`. Alasannya adalah log tersebut tidak berkolerasi dengan aktivitas mencurigakan lainnya di dalam *host*, seperti eksekusi *malware*, percobaan *brute-force*, atau kompromi akun yang biasanya mengikuti sebuah serangan *phishing*.

## Benchmark & Reduksi Alert
Penerapan *soc_classifier* menggunakan Qwen 2B memberikan efisiensi yang masif terhadap lingkungan pemantauan. Berikut adalah hasil *benchmark* dari implementasi tersebut:

* **Total Alerts Sebelum AI:** 12.211 alerts
* **Total Alerts Sesudah AI:** 3.190 alerts
* **Total Alerts yang Direduksi:** 9.021 alerts

**Persentase Reduksi:**
Sistem berhasil mengurangi *noise* peringatan sebesar **~73.88%**. Penurunan drastis ini mengoptimalkan beban kerja tim *Security Operations*, memastikan bahwa investigasi dan triase hanya difokuskan pada sisa ±26% peringatan yang telah tersaring oleh kecerdasan buatan.

