

# 🛡️ DesignGuard: Asisten Analisis Keamanan SSDLC

[](https://www.python.org/downloads/)
[](https://opensource.org/licenses/MIT)
[](https://streamlit.io)
[](https://www.google.com/search?q=https://research.ibm.com/blog/retrieval-augmented-generation)

Asisten berbasis LLM-RAG yang dirancang untuk memfasilitasi evaluasi keamanan pada fase desain *Secure Software Development Lifecycle* (SSDLC).

-----


## 📌 Tentang Proyek

**DesignGuard** adalah sebuah alat bantu berbasis web yang dirancang untuk mengatasi salah satu tantangan paling krusial dalam keamanan perangkat lunak: identifikasi dan mitigasi cacat desain (*Insecure Design*) pada tahap awal pengembangan [cite: 294-295]. [cite\_start]Banyak organisasi masih kesulitan menghubungkan spesifikasi fitur teknis dengan potensi ancaman dan kontrol keamanan yang relevan[cite: 297].

Proyek ini bergeser dari paradigma chatbot konvensional menuju fasilitator terstruktur. Dengan menggunakan antarmuka **Feature Security Profiler**, pengembang dapat secara sistematis memetakan konteks desain mereka. Sistem kemudian memanfaatkan arsitektur *Retrieval-Augmented Generation* (RAG) multi-strategi hibrida untuk menganalisis profil tersebut terhadap basis pengetahuan keamanan yang dikurasi, menghasilkan laporan analisis yang dapat ditindaklanjuti.

Tujuan utamanya adalah untuk menjembatani kesenjangan antara tim pengembangan dan proses keamanan formal, menjadikan *security by design* lebih praktis dan dapat diakses.

## ✨ Fitur Utama

  - [cite\_start]**Antarmuka Terstruktur:** Menggunakan form **Feature Security Profiler** untuk menangkap konteks desain yang kaya dan konsisten, menggantikan input teks bebas yang ambigu[cite: 462].
  - [cite\_start]**Dual Knowledge Base:** Memisahkan basis pengetahuan secara logis menjadi **Security Requirements DB** (OWASP ASVS, NIST SSDF) dan **Threat Patterns DB** (CWE, CAPEC) untuk analisis yang seimbang[cite: 395].
  - [cite\_start]**Retrieval Multi-Strategi Hibrida:** Menggabungkan pencarian semantik dengan pencarian kata kunci yang ditargetkan untuk meningkatkan presisi dalam menemukan referensi teknis spesifik seperti CWE dan CAPEC [cite: 406-408].
  - **Ekspansi Kueri Berbasis Risiko:** Secara cerdas menyuntikkan terminologi keamanan ke dalam kueri berdasarkan input pengembang, meningkatkan relevansi dokumen yang diambil.
  - [cite\_start]**Output Analisis Komprehensif:** Menghasilkan laporan terstruktur yang mencakup *Security Requirements Checklist*, *Threat Scenarios*, dan *Mitigation Strategies* yang konkret dan dapat ditindaklanjuti[cite: 285].
  - [cite\_start]**Berbasis Bukti dan Dapat Dilacak:** Setiap rekomendasi didasarkan pada dokumen sumber yang jelas, mengurangi risiko halusinasi LLM dan meningkatkan kepercayaan[cite: 287].

## 🏛️ Arsitektur Sistem

[cite\_start]Sistem DesignGuard dibangun di atas arsitektur empat lapisan fungsional [cite: 356-359]:

1.  **Knowledge Base Layer:** Fondasi data yang berisi dokumen-dokumen keamanan yang telah dikurasi dan diklasifikasikan.
2.  **User Interface Layer:** Antarmuka web berbasis Streamlit yang menyajikan **Feature Security Profiler** kepada pengguna.
3.  **Embedding & Retrieval Layer:** Lapisan yang bertanggung jawab untuk memproses, mengindeks (menggunakan ChromaDB), dan mengambil informasi dari *knowledge base* melalui strategi hibrida.
4.  **Reasoning and Generation Layer:** Inti sistem yang menggunakan LLM (Llama 3.1 via Groq) untuk menganalisis konteks yang diberikan dan menghasilkan laporan keamanan terstruktur.

## 🚀 Panduan Memulai

Untuk menjalankan salinan lokal dari DesignGuard, ikuti langkah-langkah berikut.

### Prasyarat

Pastikan Anda memiliki Python 3.9+ terinstal di sistem Anda.

### Instalasi

1.  **Clone repositori ini:**

    ```bash
    git clone https://github.com/nama-anda/designguard.git
    cd designguard
    ```

2.  **Instal dependensi yang diperlukan:**

    ```bash
    pip install -r requirements.txt
    ```

3.  **Siapkan API Key:**

      - Salin file `config.example.json` menjadi `config.json`.
      - Masukkan **GROQ\_API\_KEY** Anda ke dalam file `config.json`.
        ```json
        {
            "GROQ_API_KEY": "grok_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        }
        ```

4.  **Bangun Knowledge Base (Vector Database):**

      - Tempatkan dokumen sumber Anda (PDF, CSV, XML, MD, dll.) di dalam direktori `data/security_requirements` dan `data/threat_patterns`.
      - Jalankan skrip pemrosesan untuk membuat *vector store* ChromaDB.
        ```bash
        python CHATBOT_vectorizedoc.py
        ```
      - Proses ini mungkin memakan waktu beberapa saat tergantung pada jumlah dan ukuran dokumen Anda.

5.  **Jalankan Aplikasi Streamlit:**

    ```bash
    streamlit run CHATBOT_main.py
    ```

    Buka browser Anda dan navigasikan ke `http://localhost:8501`.

## 📖 Cara Penggunaan

1.  **Buka Aplikasi:** Setelah aplikasi berjalan, Anda akan disambut oleh antarmuka **Feature Security Profiler**.
2.  **Isi Profil Fitur:** Lengkapi form dengan detail mengenai desain fitur yang ingin Anda analisis. Semakin detail input Anda, semakin spesifik analisis yang dihasilkan.
3.  **Hasilkan Analisis:** Klik tombol **"Generate Security Analysis"**.
4.  **Tinjau Hasil:** Sistem akan memproses profil Anda dan menampilkan laporan analisis yang terstruktur di bawah form.
5.  **Eksplorasi Referensi:** Anda dapat membuka bagian **"Knowledge Base References"** untuk melihat dokumen sumber yang digunakan oleh LLM dalam menghasilkan analisis.

## 📂 Struktur Knowledge Base

Untuk hasil terbaik, letakkan dokumen sumber Anda di dalam direktori `data/` dengan struktur sebagai berikut:

  - `data/security_requirements/`: Tempatkan semua dokumen yang berkaitan dengan kontrol keamanan, standar, dan praktik terbaik di sini.
      - *Contoh: `OWASP_ASVS.csv`, `NIST_SSDF.pdf`*
  - `data/threat_patterns/`: Tempatkan semua dokumen yang berkaitan dengan kerentanan, pola serangan, dan taksonomi kelemahan di sini.
      - *Contoh: `cwec_v4.17.xml`, `capec_v3.9.xml`, `KEV.csv`*

Skrip `CHATBOT_vectorizedoc.py` akan secara otomatis memproses file dalam direktori ini.

## 🤝 Kontribusi

Kontribusi adalah hal yang membuat komunitas sumber terbuka menjadi tempat yang luar biasa untuk belajar, menginspirasi, dan berkreasi. Setiap kontribusi yang Anda buat sangat **dihargai**.

Jika Anda memiliki saran untuk memperbaikinya, silakan fork repo dan buat *pull request*. Anda juga bisa membuka *issue* dengan tag "enhancement".

1.  Fork Proyek
2.  Buat Branch Fitur Anda (`git checkout -b feature/AmazingFeature`)
3.  Commit Perubahan Anda (`git commit -m 'Add some AmazingFeature'`)
4.  Push ke Branch (`git push origin feature/AmazingFeature`)
5.  Buka Pull Request

## 📄 Lisensi

Didistribusikan di bawah Lisensi MIT. Lihat `LICENSE` untuk informasi lebih lanjut.

## 📞 Kontak

Agry Zharfa - agry.zharfa@student.poltekssn.ac.id

Tautan Proyek: [https://github.com/nama-anda/designguard](https://www.google.com/search?q=https://github.com/nama-anda/designguard)
