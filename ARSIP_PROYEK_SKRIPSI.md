# RANGKUMAN ARSITEKTUR & METODOLOGI SISTEM UNTUK PENULISAN SKRIPSI

Dokumen ini merupakan catatan komprehensif implementasi teknis sistem pertahanan web yang telah dibangun. Dokumen ini dapat dibaca oleh AI pada sesi chat baru kapan saja untuk membantu revisi naskah skripsi (Bab 3 Metodologi, Bab 4 Hasil & Pembahasan, Bab 5 Kesimpulan).

---

## 1. Identitas & Ruang Lingkup Proyek
* **Topik:** Rancang Bangun Sistem Keamanan Aplikasi Web SIAKAD berbasis Machine Learning (Multiclass Classification) dan Security Operations Center (SOC) Threat Intelligence.
* **Aplikasi Utama (Protected Asset):** Sistem Informasi Akademik (SIAKAD) berbasis Laravel di `c:\laragon\www\prosiakad`.
* **Layanan Deteksi (Security Engine):** ML Microservice berbasis Flask di `c:\laragon\www\ml-service` (port 5000).

---

## 2. Arsitektur Pertahanan & Mode IDS (Intrusion Detection System)
* **Filosofi Pertahanan:** 
  Sistem dirancang sebagai **IDS (Intrusion Detection System)** dengan kapabilitas remediasi manual (*Semi-Automated Response*).
* **Alur Deteksi (*WafMiddleware*):**
  1. Pengguna/Penyerang mengirim request HTTP ke SIAKAD.
  2. [`WafMiddleware.php`](file:///c:/laragon/www/prosiakad/app/Http/Middleware/WafMiddleware.php) melakukan pengecekan awal pada tabel `blocked_ips` (SQLite). Jika IP terdaftar di Blacklist, request **langsung ditolak HTTP 403 Forbidden**.
  3. Jika IP bersih, seluruh parameter input (Query string, Request Body/POST, Header User-Agent, URI) diekstraksi dan dikirim secara asinkron/cepat ke endpoint `/predict` microservice ML.
  4. Model ML memprediksi kategori lalu lintas dan tingkat keyakinan (*confidence score*).
  5. Karena beroperasi sebagai **IDS**, jika terdeteksi serangan, request **TIDAK langsung di-drop otomatis oleh aplikasi**, melainkan tetap diteruskan ke controller aplikasi (membiarkan aplikasi menangani secara aman / *secure coding*), sementara insiden dicatat ke basis data SOC dan notifikasi darurat dikirim ke analis keamanan.
* **Aksi Remediasi Manual (IP Blacklist):**
  * Analis SOC memegang kendali penuh (*human-in-the-loop*).
  * Analis dapat memeriksa bukti serangan (payload, parameter, URL) melalui pop-up modal insiden di Dashboard, lalu menekan tombol **"Blokir IP"**.
  * IP penyerang seketika masuk ke tabel `blocked_ips` dan aksesnya ke SIAKAD langsung terputus secara permanen (HTTP 403) hingga Analis menekan **"Buka Blokir"**.

---

## 3. Komponen Machine Learning & Ekstraksi Fitur
* **Model yang Digunakan:** Random Forest Classifier (Multiclass: `Normal`, `SQL Injection`, `XSS`, `Path Traversal`).
* **Format Model:** Serialized pickle model (`best_multiclass_rf_model.pkl`), TF-IDF vectorizer (`tfidf_vectorizer.pkl`), dan label encoder (`label_encoder.pkl`).
* **Fitur yang Diekstraksi ([`preprocessing.py`](file:///c:/laragon/www/ml-service/preprocessing.py)):**
  1. *Lexical & Statistical Features:* Panjang payload, rasio karakter khusus, jumlah tanda kurung/petik, rasio digit, spasi ganda.
  2. *Keyword Presence (Pattern Matching):* Indikator kata kunci SQLi (`UNION`, `SELECT`, `--`, `OR 1=1`), XSS (`<script>`, `onerror=`, `javascript:`), Path Traversal (`../`, `..\`, `/etc/passwd`).
  3. *TF-IDF Vectorization:* Representasi frekuensi n-gram karakter/kata dari payload.
* **Performa Model:**
  * Waktu inferensi rata-rata (*latency*): **~1.2 ms per request** (sangat cepat, tidak membebani kinerja server).

---

## 4. Sistem Alerting Real-Time (Telegram Bot)
* **Modul:** [`telegram_service.py`](file:///c:/laragon/www/ml-service/telegram_service.py)
* **Kredensial:** Bot Token `8979337868:AAGqEKGlIz3bPZX0lwozScs6vFHrhf9RDco`, Chat ID `7295712328`.
* **Threshold Peringatan:** Minimum confidence **60% (`0.60`)** untuk memfilter false positive ringan.
* **Mekanisme Eksekusi:** Berjalan di *background thread* terpisah (`threading.Thread`) sehingga latensi jaringan Telegram sama sekali tidak memperlambat respon API `/predict`.
* **Keamanan Pesan:** Menggunakan parser `HTML` yang dibungkus dengan sanitasi `html.escape()` untuk mencegah karakter payload serangan merusak parser Telegram.

---

## 5. Antarmuka SOC Threat Intelligence Dashboard
* **Framework Frontend:** HTML5, Tailwind CSS, FontAwesome 6, Chart.js v4, Hammer.js, Chart.js Zoom Plugin.
* **Fitur Utama:**
  1. **High-Level Metric Cards:** Total Request, Threat Ratio (%), Total Attacks, Normal Traffic, Engine Latency, dan Uptime.
  2. **Grafik Fluktuasi Serangan Real-Time (Crypto-Style Interaction):**
     * Linimasa kontinu dari `00:00` hingga saat ini (mengisi `0` pada menit kosong).
     * **Drag to Pan:** Kursor mouse berubah menjadi `grab/grabbing`, memungkinkan analis menggeser grafik secara horizontal untuk meninjau aktivitas serangan di jam-jam sebelumnya.
     * **Zoom In/Out:** Scroll mouse wheel untuk memperbesar detail hingga skala menit rapat (*per menit*) atau memperkecil hingga ringkasan harian luas (*per jam*).
     * **Status Cerdas (LIVE vs RIWAYAT):** Saat menggeser ke riwayat masa lampau, background polling 3 detik tidak mereset posisi pandang analis. Tombol `[Live Terkini]` disediakan untuk kembali ke pemantauan waktu nyata.
  3. **Proporsi Jenis Ancaman:** Doughnut chart distribusi SQLi, XSS, dan Path Traversal.
  4. **Navigasi Tab:** 
     * *Tab 1: Log Aktivitas Serangan* (dilengkapi pencarian, filter kategori, pemilih tanggal per hari/arsip, dan paginasi 10 data).
     * *Tab 2: IP Blacklist* (badge total IP terblokir, daftar IP, tanggal pemblokiran, dan tombol Buka Blokir).
  5. **Pop-up Detail Insiden:** Menampilkan payload lengkap, confidence score, User-Agent, tombol investigasi, dan tombol toggle Blokir / Buka Blokir IP.

---

## 6. Petunjuk untuk Sesi Chat Baru
Saat Anda membuka chat baru khusus untuk menulis atau merevisi bab-bab skripsi, Anda cukup memberikan instruksi seperti berikut:

> *"Halo, kita akan merevisi naskah skripsi saya terkait sistem deteksi serangan SIAKAD berbasis Machine Learning dan Dashboard SOC. Silakan baca file `ARSIP_PROYEK_SKRIPSI.md` di root proyek untuk memahami seluruh arsitektur teknis dan hasil yang sudah kita buat."*

