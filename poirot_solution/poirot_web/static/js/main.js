document.addEventListener('DOMContentLoaded', () => {
    // HTML elemanlarını seçiyoruz
    const scanBtn = document.getElementById('scanBtn');
    const targetInput = document.getElementById('targetInput');
    const resultArea = document.getElementById('resultArea');

    // Butona tıklanma olayını dinle
    scanBtn.addEventListener('click', async () => {
        const target = targetInput.value.trim();

        // 1. Boş kontrolü
        if (!target) {
            alert("Mon ami, boşluğu tarayamam! Lütfen bir hedef gir.");
            return;
        }

        // 2. Arayüzü 'Yükleniyor' moduna al
        scanBtn.disabled = true;
        scanBtn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Dedektif Çalışıyor...';
        resultArea.style.display = 'block';
        resultArea.innerHTML = '<div class="alert alert-info">🕵️‍♂️ Veriler toplanıyor, lütfen bekleyiniz... (Bu işlem 5-10 saniye sürebilir)</div>';

        try {
            // 3. API'ye İsteği Gönder (POST)
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ target: target })
            });

            const data = await response.json();

            // 4. Sonucu Ekrana Bas
            if (data.success) {
                renderSuccess(data); // Başarılıysa tabloyu çiz
            } else {
                resultArea.innerHTML = `<div class="alert alert-danger">❌ Hata: ${data.error}</div>`;
            }

        } catch (error) {
            console.error(error);
            resultArea.innerHTML = `<div class="alert alert-danger">🔥 Kritik Hata: Sunucu ile iletişim kurulamadı.</div>`;
        } finally {
            // 5. Butonu eski haline getir
            scanBtn.disabled = false;
            scanBtn.innerHTML = '🔍 Taramayı Başlat';
        }
    });

    // Başarılı sonucu çizen yardımcı fonksiyon
    function renderSuccess(data) {
        let portsHtml = '';

        // DÜZELTME BURADA:
        // Dedektif (Backend) paketi açıp yolladığı için artık 'scan' ve 'ip' katmanları yok.
        // Direkt 'full_data.tcp' diyerek verilere ulaşıyoruz.
        if (data.full_data && data.full_data.tcp) {
            const ports = data.full_data.tcp;

            // Portları döngüye al
            for (const [port, details] of Object.entries(ports)) {
                portsHtml += `
                    <tr>
                        <td><span class="badge bg-primary">${port}</span></td>
                        <td>${details.name || 'Bilinmiyor'}</td>
                        <td>${details.product || ''} ${details.version || ''}</td>
                        <td>
                            <span class="badge ${details.state === 'open' ? 'bg-success' : 'bg-danger'}">
                                ${details.state.toUpperCase()}
                            </span>
                        </td>
                    </tr>
                `;
            }
        } else {
            portsHtml = '<tr><td colspan="4" class="text-center">Açık port bulunamadı veya detay yok.</td></tr>';
        }

        // HTML şablonunu oluştur
        resultArea.innerHTML = `
            <div class="card shadow">
                <div class="card-header bg-success text-white">
                    <h5 class="mb-0">✅ Tarama Tamamlandı: ${data.hostname || document.getElementById('targetInput').value}</h5>
                </div>
                <div class="card-body">
                    <p><strong>IP Adresi:</strong> ${data.ip}</p>
                    <p><strong>Durum:</strong> ${data.state.toUpperCase()}</p>
                    <hr>
                    <h6>🔎 Açık Portlar ve Servisler:</h6>
                    <div class="table-responsive">
                        <table class="table table-hover table-striped">
                            <thead>
                                <tr>
                                    <th>Port</th>
                                    <th>Servis</th>
                                    <th>Versiyon</th>
                                    <th>Durum</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${portsHtml}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        `;
    }
});