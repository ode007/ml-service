// SOC Dashboard Real-time Polling & Windows Security Style History Controller

// Global cache untuk data insiden
let cachedIncidents = {};
let currentActivePayload = '';
let currentActiveIp = '';
let currentActiveCategory = '';
let currentActiveIsBlocked = false;
let currentTableTab = 'logs';

// Helper Escape HTML
function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Helper untuk memperbarui tombol blokir di modal
function updateModalBlockButton(isBlocked) {
    currentActiveIsBlocked = !!isBlocked;
    const btn = document.getElementById('btn-modal-block-ip');
    const icon = document.getElementById('modal-block-btn-icon');
    const text = document.getElementById('modal-block-btn-text');
    if (!btn || !text) return;

    if (isBlocked) {
        btn.className = "px-3.5 py-1.5 rounded-lg bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 text-xs font-medium border border-emerald-800/80 transition flex items-center space-x-1.5 cursor-pointer";
        if (icon) icon.className = "fa-solid fa-lock-open";
        text.innerText = "Buka Blokir IP";
    } else {
        btn.className = "px-3.5 py-1.5 rounded-lg bg-rose-950/80 hover:bg-rose-900 text-rose-300 text-xs font-medium border border-rose-800/80 transition flex items-center space-x-1.5 cursor-pointer";
        if (icon) icon.className = "fa-solid fa-ban";
        text.innerText = "Blokir IP";
    }
}

// Fungsi Global untuk Membuka Modal Detail Insiden
window.showIncidentDetail = function(id) {
    const inc = cachedIncidents[id] || cachedIncidents[String(id)] || cachedIncidents[Number(id)];
    if (!inc) return;

    currentActivePayload = inc.payload || '';
    currentActiveIp = inc.ip_address || '127.0.0.1';
    currentActiveCategory = inc.category || 'Threat';

    // 1. Header Info
    document.getElementById('modal-timestamp').innerText = inc.timestamp;

    // 2. Detected
    const detectedEl = document.getElementById('modal-detected');
    if (detectedEl) detectedEl.innerText = inc.category;

    // 3. Date & Details
    document.getElementById('modal-date').innerText = inc.timestamp;

    const detailsEl = document.getElementById('modal-details');
    if (inc.category === 'SQL Injection') {
        detailsEl.innerText = "Muatan HTTP mengandung pola manipulasi query database terstruktur (SQLi) yang berpotensi merusak integritas atau membocorkan rekaman data SIAKAD.";
    } else if (inc.category === 'XSS') {
        detailsEl.innerText = "Muatan HTTP terdeteksi mengandung tag atau skrip eksekusi berbahaya (Cross-Site Scripting) yang berupaya menjalankan injeksi script pada peramban korban.";
    } else if (inc.category === 'Path Traversal') {
        detailsEl.innerText = "Muatan HTTP mengandung upaya navigasi direktori terlarang (dot-dot-slash / traversal) yang mencoba mengakses berkas sensitif di luar web root.";
    } else {
        detailsEl.innerText = "Aktivitas anomali terdeteksi melanggar pola lalu lintas normal pada sistem informasi akademik.";
    }

    // 4. Threat Engine & Machine Learning Analysis
    const detSourceEl = document.getElementById('modal-detection-source'); if (detSourceEl) detSourceEl.innerText = inc.detection_source || 'ML_MODEL';
    const confPercent = (inc.confidence * 100).toFixed(1);
    const modalConfEl = document.getElementById('modal-confidence');
    modalConfEl.innerText = `${confPercent}%`;
    if (parseFloat(confPercent) >= 60.0) {
        modalConfEl.className = "font-mono font-bold text-rose-400 text-sm whitespace-nowrap";
        modalConfEl.style.color = "#f43f5e";
    } else {
        modalConfEl.className = "font-mono font-bold text-slate-200 text-sm whitespace-nowrap";
        modalConfEl.style.color = "";
    }
    document.getElementById('modal-confidence-bar').style.width = `${confPercent}%`;

    // 5. Affected Items
    document.getElementById('modal-affected-url').innerText = inc.url || 'N/A';
    document.getElementById('modal-affected-ip').innerText = inc.ip_address || '127.0.0.1';
    document.getElementById('modal-affected-method').innerText = inc.method || 'GET';
    document.getElementById('modal-affected-payload').innerText = inc.payload || '(Kosong)';
    document.getElementById('modal-affected-ua').innerText = inc.user_agent || 'Mozilla/5.0';

    // 6. Periksa apakah IP ini sedang diblokir
    updateModalBlockButton(false);
    fetch(`/api/blocked-ips/check?ip=${encodeURIComponent(currentActiveIp)}`)
        .then(res => res.json())
        .then(data => {
            updateModalBlockButton(!!data.is_blocked);
        })
        .catch(err => {
            console.error('Gagal memeriksa status blokir IP:', err);
        });

    // 7. Tampilkan Modal dengan Animasi
    const modal = document.getElementById('incident-modal');
    const container = document.getElementById('modal-container');
    modal.classList.remove('hidden');
    setTimeout(() => {
        modal.classList.remove('opacity-0');
        container.classList.remove('scale-95');
        container.classList.add('scale-100');
    }, 10);
};

// Fungsi Global untuk Menutup Modal
window.closeIncidentModal = function() {
    const modal = document.getElementById('incident-modal');
    const container = document.getElementById('modal-container');
    modal.classList.add('opacity-0');
    container.classList.remove('scale-100');
    container.classList.add('scale-95');
    setTimeout(() => {
        modal.classList.add('hidden');
    }, 200);
};

// Fungsi Global untuk Menyalin Payload
window.copyPayload = function() {
    if (!currentActivePayload) return;
    navigator.clipboard.writeText(currentActivePayload).then(() => {
        const textSpan = document.getElementById('copy-btn-text');
        const originalText = textSpan.innerText;
        textSpan.innerText = 'Tersalin!';
        setTimeout(() => {
            textSpan.innerText = originalText;
        }, 1500);
    }).catch(err => {
        console.error('Gagal menyalin:', err);
    });
};

// Fungsi Global untuk Toggle Blokir / Buka Blokir IP dari Modal Detail
window.toggleBlockActiveIp = async function() {
    if (!currentActiveIp) return;
    const btn = document.getElementById('btn-modal-block-ip');
    const textSpan = document.getElementById('modal-block-btn-text');
    const originalText = textSpan ? textSpan.innerText : '';
    if (textSpan) textSpan.innerText = 'Memproses...';
    if (btn) btn.disabled = true;

    try {
        if (currentActiveIsBlocked) {
            // Unblock
            const res = await fetch('/api/blocked-ips/unblock', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip_address: currentActiveIp })
            });
            const data = await res.json();
            if (res.ok) {
                updateModalBlockButton(false);
                if (window.refreshBlockedIps) window.refreshBlockedIps();
            } else {
                alert(data.message || 'Gagal membuka blokir IP');
                updateModalBlockButton(true);
            }
        } else {
            // Block
            const reason = `Terdeteksi serangan ${currentActiveCategory} pada SIAKAD`;
            const res = await fetch('/api/blocked-ips', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip_address: currentActiveIp, reason: reason })
            });
            const data = await res.json();
            if (res.ok) {
                updateModalBlockButton(true);
                if (window.refreshBlockedIps) window.refreshBlockedIps();
            } else {
                alert(data.message || 'Gagal memblokir IP');
                updateModalBlockButton(false);
            }
        }
    } catch (e) {
        console.error('Error saat toggle status blokir IP:', e);
        alert('Terjadi kesalahan saat memproses status blokir IP');
        if (textSpan) textSpan.innerText = originalText;
    } finally {
        if (btn) btn.disabled = false;
    }
};

// Fungsi Global untuk Mengganti Tab Tabel (Log Serangan vs IP Blacklist)
window.switchTableTab = function(tabName) {
    currentTableTab = tabName;
    const tabLogs = document.getElementById('tab-content-logs');
    const tabBlacklist = document.getElementById('tab-content-blacklist');
    const btnLogs = document.getElementById('tab-btn-logs');
    const btnBlacklist = document.getElementById('tab-btn-blacklist');

    if (tabName === 'logs') {
        if (tabLogs) tabLogs.classList.remove('hidden');
        if (tabBlacklist) tabBlacklist.classList.add('hidden');
        if (btnLogs) {
            btnLogs.className = "px-4 py-2.5 text-xs font-bold border-b-2 border-cyan-400 text-cyan-400 flex items-center gap-2 transition cursor-pointer";
        }
        if (btnBlacklist) {
            btnBlacklist.className = "px-4 py-2.5 text-xs font-bold border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2 transition cursor-pointer";
        }
    } else if (tabName === 'blacklist') {
        if (tabLogs) tabLogs.classList.add('hidden');
        if (tabBlacklist) tabBlacklist.classList.remove('hidden');
        if (btnBlacklist) {
            btnBlacklist.className = "px-4 py-2.5 text-xs font-bold border-b-2 border-rose-500 text-rose-400 flex items-center gap-2 transition cursor-pointer";
        }
        if (btnLogs) {
            btnLogs.className = "px-4 py-2.5 text-xs font-bold border-b-2 border-transparent text-slate-400 hover:text-slate-200 flex items-center gap-2 transition cursor-pointer";
        }
        window.refreshBlockedIps();
    }
};

// Fungsi Global untuk Memuat Daftar IP Blacklist
window.refreshBlockedIps = async function() {
    try {
        const res = await fetch('/api/blocked-ips');
        if (!res.ok) return;
        const data = await res.json();

        // Update badge count
        const badge = document.getElementById('blacklist-badge-count');
        if (badge) badge.innerText = data.total || 0;

        const countText = document.getElementById('blacklist-count-text');
        if (countText) countText.innerText = data.total || 0;

        const tbody = document.getElementById('blacklist-table-body');
        if (!tbody) return;

        if (!data.blocked_ips || data.blocked_ips.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="px-4 py-8 text-center text-slate-500">
                        <i class="fa-solid fa-shield-check text-2xl text-emerald-500 mb-2"></i>
                        <p>Tidak ada IP yang sedang diblokir saat ini.</p>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = data.blocked_ips.map(item => `
            <tr class="hover:bg-slate-800/40 transition">
                <td class="px-4 py-3 font-mono font-bold text-rose-400 whitespace-nowrap">
                    <span class="inline-flex items-center gap-1.5">
                        <i class="fa-solid fa-ban text-xs text-rose-500"></i>
                        <span>${escapeHtml(item.ip_address)}</span>
                    </span>
                </td>
                <td class="px-4 py-3 text-slate-300 max-w-xs truncate" title="${escapeHtml(item.reason || '')}">
                    ${escapeHtml(item.reason || 'Terdeteksi aktivitas berbahaya')}
                </td>
                <td class="px-4 py-3 font-mono text-slate-400 whitespace-nowrap">
                    ${escapeHtml(item.blocked_at)}
                </td>
                <td class="px-4 py-3 whitespace-nowrap">
                    <span class="px-2 py-0.5 rounded-full font-semibold text-[10px] bg-rose-950 text-rose-300 border border-rose-800 inline-flex items-center gap-1">
                        <span class="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse"></span>
                        <span>TERBLOKIR</span>
                    </span>
                </td>
                <td class="px-4 py-3 text-right whitespace-nowrap">
                    <button onclick="unblockIpAddress('${escapeHtml(item.ip_address)}')"
                        class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-emerald-400 hover:text-emerald-300 border border-slate-700 font-semibold text-[11px] inline-flex items-center space-x-1.5 transition cursor-pointer">
                        <i class="fa-solid fa-lock-open text-[10px]"></i>
                        <span>Buka Blokir</span>
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        console.error('Gagal memuat daftar IP terblokir:', e);
    }
};

// Fungsi Global untuk Membuka Blokir dari Baris Tabel
window.unblockIpAddress = async function(ip) {
    if (!confirm(`Apakah Anda yakin ingin membuka blokir untuk IP ${ip}?`)) return;
    try {
        const res = await fetch('/api/blocked-ips/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip_address: ip })
        });
        const data = await res.json();
        if (res.ok) {
            window.refreshBlockedIps();
            if (currentActiveIp === ip) {
                updateModalBlockButton(false);
            }
        } else {
            alert(data.message || 'Gagal membuka blokir IP');
        }
    } catch (e) {
        console.error('Error saat membuka blokir IP:', e);
        alert('Terjadi kesalahan saat membuka blokir IP');
    }
};

document.addEventListener('DOMContentLoaded', () => {
    let trendChart = null;
    let categoryChart = null;
    let isTrendUserNavigating = false; // State: apakah user sedang menggeser/zoom riwayat lampau

    // Registrasi plugin zoom jika tersedia
    if (typeof Chart !== 'undefined' && typeof ChartZoom !== 'undefined') {
        try {
            Chart.register(ChartZoom);
        } catch (e) {
            // Already registered
        }
    }

    // Helper status navigasi grafik (Live vs Riwayat Lampau)
    const setTrendNavigating = (navigating) => {
        isTrendUserNavigating = navigating;
        const resetBtn = document.getElementById('btn-reset-trend-zoom');
        const badge = document.getElementById('trend-live-badge');
        const statusText = document.getElementById('trend-live-status-text');

        if (navigating) {
            if (resetBtn) {
                resetBtn.classList.remove('hidden');
                resetBtn.classList.add('inline-flex');
            }
            if (badge) {
                badge.className = 'inline-flex items-center gap-1.5 text-xs font-mono px-2 py-1 rounded bg-amber-950/40 border border-amber-800/60 text-amber-400';
            }
            if (statusText) {
                statusText.innerText = 'RIWAYAT';
            }
        } else {
            if (resetBtn) {
                resetBtn.classList.remove('inline-flex');
                resetBtn.classList.add('hidden');
            }
            if (badge) {
                badge.className = 'inline-flex items-center gap-1.5 text-xs font-mono px-2 py-1 rounded bg-slate-900 border border-slate-800 text-emerald-400';
            }
            if (statusText) {
                statusText.innerText = 'LIVE';
            }
        }
    };

    // Fungsi kembali ke jendela Live terkini
    const snapToLive = () => {
        setTrendNavigating(false);
        if (!trendChart || !trendChart.data.labels) return;
        const total = trendChart.data.labels.length;
        const liveWindow = 25; // perlihatkan 25 menit terakhir saat mode Live
        if (total > liveWindow) {
            trendChart.options.scales.x.min = total - liveWindow;
            trendChart.options.scales.x.max = total - 1;
        } else {
            delete trendChart.options.scales.x.min;
            delete trendChart.options.scales.x.max;
        }
        trendChart.update();
    };

    // --- Inisialisasi Grafik Chart.js ---
    const initCharts = () => {
        // 1. Line Chart: Tren Fluktuasi Serangan
        const trendCanvas = document.getElementById('attackTrendChart');
        const trendCtx = trendCanvas.getContext('2d');
        trendChart = new Chart(trendCtx, {
            type: 'line',
            data: {
                labels: ['00:00'],
                datasets: [
                    {
                        label: 'Serangan (Attacks)',
                        data: [0],
                        borderColor: '#F43F5E',
                        backgroundColor: 'rgba(244, 63, 94, 0.15)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.25,
                        pointBackgroundColor: '#F43F5E',
                        pointBorderColor: '#FDA4AF',
                        pointRadius: 1.5,
                        pointHoverRadius: 5,
                        pointHitRadius: 8
                    },
                    {
                        label: 'Normal Traffic',
                        data: [0],
                        borderColor: '#10B981',
                        backgroundColor: 'transparent',
                        borderWidth: 1.5,
                        borderDash: [4, 4],
                        fill: false,
                        tension: 0.25,
                        pointRadius: 1,
                        pointHoverRadius: 4,
                        pointHitRadius: 8
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: {
                    mode: 'index',
                    intersect: false
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#94A3B8',
                            font: { size: 11 }
                        }
                    },
                    tooltip: {
                        backgroundColor: '#0F172A',
                        borderColor: '#334155',
                        borderWidth: 1,
                        titleColor: '#38BDF8',
                        bodyColor: '#F8FAFC',
                        titleFont: { size: 12, weight: 'bold' },
                        bodyFont: { size: 11 },
                        padding: 10,
                        displayColors: true,
                        callbacks: {
                            title: function(context) {
                                return 'Waktu: ' + context[0].label + ' WIB';
                            }
                        }
                    },
                    zoom: {
                        pan: {
                            enabled: true,
                            mode: 'x',
                            modifierKey: null,
                            threshold: 4,
                            onPanStart: function() {
                                setTrendNavigating(true);
                            }
                        },
                        zoom: {
                            wheel: {
                                enabled: true,
                                speed: 0.05
                            },
                            pinch: {
                                enabled: true
                            },
                            mode: 'x',
                            onZoomStart: function() {
                                setTrendNavigating(true);
                            }
                        },
                        limits: {
                            x: {
                                min: 0,
                                minRange: 8
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(30, 41, 59, 0.5)' },
                        ticks: { 
                            color: '#64748B', 
                            font: { size: 10 },
                            autoSkip: true,
                            maxTicksLimit: 14,
                            maxRotation: 0,
                            autoSkipPadding: 8
                        }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(30, 41, 59, 0.5)' },
                        ticks: { color: '#64748B', font: { size: 10 }, precision: 0 }
                    }
                }
            }
        });

        // Interaksi Canvas Grab / Grabbing
        trendCanvas.addEventListener('mousedown', () => {
            trendCanvas.classList.remove('cursor-grab');
            trendCanvas.classList.add('cursor-grabbing');
        });
        window.addEventListener('mouseup', () => {
            if (trendCanvas) {
                trendCanvas.classList.remove('cursor-grabbing');
                trendCanvas.classList.add('cursor-grab');
            }
        });
        trendCanvas.addEventListener('dblclick', () => {
            snapToLive();
        });

        // Tombol Interaktif Zoom In (+) & Zoom Out (-)
        const btnZoomIn = document.getElementById('btn-trend-zoom-in');
        if (btnZoomIn) {
            btnZoomIn.addEventListener('click', () => {
                if (!trendChart) return;
                setTrendNavigating(true);
                trendChart.zoom(1.3);
            });
        }
        const btnZoomOut = document.getElementById('btn-trend-zoom-out');
        if (btnZoomOut) {
            btnZoomOut.addEventListener('click', () => {
                if (!trendChart) return;
                setTrendNavigating(true);
                trendChart.zoom(0.7);
            });
        }
        const btnResetZoom = document.getElementById('btn-reset-trend-zoom');
        if (btnResetZoom) {
            btnResetZoom.addEventListener('click', snapToLive);
        }

        // 2. Doughnut Chart: Distribusi Kategori
        const catCtx = document.getElementById('categoryChart').getContext('2d');
        categoryChart = new Chart(catCtx, {
            type: 'doughnut',
            data: {
                labels: ['SQL Injection', 'XSS', 'Path Traversal'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#EF4444', '#F59E0B', '#A855F7'],
                    borderColor: '#111827',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#94A3B8',
                            boxWidth: 12,
                            font: { size: 10 }
                        }
                    }
                },
                cutout: '70%'
            }
        });
    };

    let currentPage = 1;
    let totalPages = 1;

    // Helper tanggal hari ini (format YYYY-MM-DD waktu lokal)
    const getTodayLocalDate = () => {
        const d = new Date();
        const year = d.getFullYear();
        const month = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    };

    // Set nilai awal pemilih tanggal jika belum terisi
    const dateInput = document.getElementById('filter-date');
    if (dateInput && !dateInput.value) {
        dateInput.value = getTodayLocalDate();
    }

    // --- Fungsi Update Metrik & Grafik dari API ---
    const updateMetrics = async () => {
        try {
            const dateVal = document.getElementById('filter-date') ? document.getElementById('filter-date').value : '';
            const url = new URL('/api/metrics', window.location.origin);
            if (dateVal) url.searchParams.append('date', dateVal);

            const res = await fetch(url.toString());
            if (!res.ok) return;
            const data = await res.json();

            // Update Cards
            const m = data.metrics;
            document.getElementById('stat-total-requests').innerText = m.total_requests.toLocaleString();
            document.getElementById('stat-threat-ratio').innerText = `${m.threat_ratio}%`;
            document.getElementById('stat-total-attacks').innerText = m.total_attacks.toLocaleString();
            document.getElementById('stat-total-normal').innerText = m.total_normal.toLocaleString();

            // Update Engine Status & Latency
            const eng = data.engine;
            document.getElementById('stat-latency').innerText = `~${eng.latency_ms} ms`;
            document.getElementById('stat-uptime').innerText = eng.uptime;
            document.getElementById('nav-latency').innerText = `~${eng.latency_ms} ms`;
            document.getElementById('nav-engine-status').innerText = eng.status.toUpperCase();

            // Update Timestamp Last Updated
            const now = new Date();
            document.getElementById('last-updated').innerText = now.toLocaleTimeString();

            // Update Line Chart (Mendukung Real-Time & Riwayat Lampau)
            if (trendChart && data.trend) {
                trendChart.data.labels = data.trend.labels;
                trendChart.data.datasets[0].data = data.trend.attacks;
                trendChart.data.datasets[1].data = data.trend.normals;

                const totalPoints = data.trend.labels.length;
                const liveWindow = 25;

                // Perbarui limit pan & zoom secara dinamis
                if (trendChart.options.plugins && trendChart.options.plugins.zoom) {
                    trendChart.options.plugins.zoom.limits.x.min = 0;
                    trendChart.options.plugins.zoom.limits.x.max = Math.max(0, totalPoints - 1);
                    trendChart.options.plugins.zoom.limits.x.minRange = 8;
                }

                if (!isTrendUserNavigating) {
                    // Mode LIVE: pertahankan jendela fokus di menit terkini
                    if (totalPoints > liveWindow) {
                        trendChart.options.scales.x.min = totalPoints - liveWindow;
                        trendChart.options.scales.x.max = totalPoints - 1;
                    } else {
                        delete trendChart.options.scales.x.min;
                        delete trendChart.options.scales.x.max;
                    }
                } else {
                    // Mode RIWAYAT / PAN: jangan sentuh scales.x.min/max agar pandangan user tidak melompat
                }
                trendChart.update('none');
            }

            // Update Doughnut Chart
            if (categoryChart && m.category_counts) {
                const cats = m.category_counts;
                const sqli = cats['SQL Injection'] || 0;
                const xss = cats['XSS'] || 0;
                const traversal = cats['Path Traversal'] || 0;

                categoryChart.data.datasets[0].data = [sqli, xss, traversal];
                categoryChart.update('none');
            }

        } catch (err) {
            console.error('[Dashboard Polling Error]', err);
            const statusEl = document.getElementById('nav-engine-status');
            if (statusEl) {
                statusEl.innerText = 'RECONNECTING';
                statusEl.className = 'text-xs font-medium text-amber-400 tracking-wide font-mono';
            }
        }
    };

    // --- Fungsi Update Tabel Log Insiden (10 Data per Halaman + Filter Tanggal) ---
    const updateIncidentsTable = async () => {
        try {
            const cat = document.getElementById('filter-category').value;
            const search = document.getElementById('filter-search').value.trim();
            const dateVal = document.getElementById('filter-date') ? document.getElementById('filter-date').value : '';

            const url = new URL('/api/incidents', window.location.origin);
            url.searchParams.append('category', cat);
            if (search) url.searchParams.append('search', search);
            if (dateVal) url.searchParams.append('date', dateVal);
            url.searchParams.append('page', currentPage);
            url.searchParams.append('limit', 10);

            const res = await fetch(url.toString());
            if (!res.ok) return;
            const data = await res.json();

            // Update State Paginasi
            totalPages = data.total_pages || 1;
            currentPage = data.page || 1;
            const totalRecords = data.total || 0;

            const pageIndicator = document.getElementById('pagination-page-indicator');
            const pageInfo = document.getElementById('pagination-info');
            const btnPrev = document.getElementById('btn-prev-page');
            const btnNext = document.getElementById('btn-next-page');

            if (pageIndicator) pageIndicator.innerText = `${currentPage} / ${totalPages}`;
            if (pageInfo) {
                if (totalRecords > 0) {
                    const startIdx = (currentPage - 1) * 10 + 1;
                    const endIdx = Math.min(currentPage * 10, totalRecords);
                    pageInfo.innerText = `Menampilkan ${startIdx} - ${endIdx} dari ${totalRecords} insiden`;
                } else {
                    pageInfo.innerText = 'Tidak ada insiden tercatat';
                }
            }

            if (btnPrev) btnPrev.disabled = (currentPage <= 1);
            if (btnNext) btnNext.disabled = (currentPage >= totalPages || totalRecords === 0);

            const tbody = document.getElementById('incident-table-body');
            if (!data.incidents || data.incidents.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="7" class="px-4 py-8 text-center text-slate-500">
                            <i class="fa-solid fa-shield-heart text-2xl text-slate-600 mb-2"></i>
                            <p>Belum ada insiden serangan yang tercatat pada tanggal ini.</p>
                        </td>
                    </tr>
                `;
                return;
            }

            let rowsHtml = '';
            data.incidents.forEach(inc => {
                // Simpan ke cache untuk dibuka di modal
                cachedIncidents[inc.id] = inc;

                const methodBadge = inc.method === 'POST'
                    ? '<span class="px-1.5 py-0.5 rounded text-[11px] font-mono bg-amber-950 text-amber-400 border border-amber-800">POST</span>'
                    : '<span class="px-1.5 py-0.5 rounded text-[11px] font-mono bg-blue-950 text-blue-400 border border-blue-800">GET</span>';

                let catClass = 'bg-slate-800 text-slate-300';
                if (inc.category === 'SQL Injection') catClass = 'bg-rose-950 text-rose-300 border border-rose-800';
                else if (inc.category === 'XSS') catClass = 'bg-amber-950 text-amber-300 border border-amber-800';
                else if (inc.category === 'Path Traversal') catClass = 'bg-purple-950 text-purple-300 border border-purple-800';

                const confPercent = (inc.confidence * 100).toFixed(1);
                const isHighConf = parseFloat(confPercent) >= 60.0;
                const confClass = isHighConf ? 'font-mono font-bold text-rose-400 whitespace-nowrap' : 'font-mono text-slate-300 whitespace-nowrap';
                const confStyle = isHighConf ? 'style="color: #f43f5e !important; font-weight: 700;"' : '';
                const safeUrl = String(inc.url || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

                rowsHtml += `
                    <tr class="hover:bg-slate-800/40 transition cursor-pointer group" onclick="showIncidentDetail(${inc.id})">
                        <td class="px-4 py-3 font-mono text-slate-400 whitespace-nowrap">${inc.timestamp}</td>
                        <td class="px-4 py-3 font-mono font-medium text-cyan-300 whitespace-nowrap">${inc.ip_address}</td>
                        <td class="px-4 py-3 whitespace-nowrap">${methodBadge}</td>
                        <td class="px-4 py-3 max-w-xs truncate" title="${safeUrl}">
                            <span class="font-mono text-slate-200 group-hover:text-cyan-300 transition-colors">${safeUrl}</span>
                        </td>
                        <td class="px-4 py-3 whitespace-nowrap">
                            <span class="px-2 py-0.5 rounded-full font-semibold text-[11px] ${catClass}">
                                ${inc.category}
                            </span>
                        </td>
                        <td class="px-4 py-3 ${confClass}" ${confStyle}>${confPercent}%</td>
                        <td class="px-4 py-3 whitespace-nowrap" onclick="event.stopPropagation()">
                            <button onclick="showIncidentDetail(${inc.id})" 
                                class="px-2.5 py-1 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 font-semibold text-[11px] inline-flex items-center space-x-1.5 transition cursor-pointer">
                                <i class="fa-solid fa-circle-info text-[10px]"></i>
                                <span>Detail</span>
                                <i class="fa-solid fa-chevron-right text-[9px] text-cyan-300/80"></i>
                            </button>
                        </td>
                    </tr>
                `;
            });

            tbody.innerHTML = rowsHtml;

        } catch (err) {
            console.error('[Incident Log Error]', err);
        }
    };

    // --- Inisialisasi Sistem ---
    initCharts();
    updateMetrics();
    updateIncidentsTable();
    window.refreshBlockedIps();

    // Polling Interval: 3000ms (3 detik)
    const pollInterval = setInterval(() => {
        updateMetrics();
        if (currentTableTab === 'logs') {
            updateIncidentsTable();
        } else if (currentTableTab === 'blacklist') {
            window.refreshBlockedIps();
        }
    }, 3000);

    // Event Listeners Paginasi
    const btnPrev = document.getElementById('btn-prev-page');
    if (btnPrev) {
        btnPrev.addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage--;
                updateIncidentsTable();
            }
        });
    }

    const btnNext = document.getElementById('btn-next-page');
    if (btnNext) {
        btnNext.addEventListener('click', () => {
            if (currentPage < totalPages) {
                currentPage++;
                updateIncidentsTable();
            }
        });
    }

    // Event Listener Pemilih Tanggal
    if (dateInput) {
        dateInput.addEventListener('change', () => {
            currentPage = 1;
            const isToday = (dateInput.value === getTodayLocalDate() || !dateInput.value);
            if (!isToday) {
                setTrendNavigating(true);
                const statusText = document.getElementById('trend-live-status-text');
                if (statusText) statusText.innerText = 'ARSIP';
                if (trendChart) {
                    delete trendChart.options.scales.x.min;
                    delete trendChart.options.scales.x.max;
                }
            } else {
                snapToLive();
            }
            updateMetrics();
            updateIncidentsTable();
        });
    }

    const btnDateToday = document.getElementById('btn-date-today');
    if (btnDateToday && dateInput) {
        btnDateToday.addEventListener('click', () => {
            dateInput.value = getTodayLocalDate();
            currentPage = 1;
            snapToLive();
            updateMetrics();
            updateIncidentsTable();
        });
    }

    // Event Listeners Filter Kategori & Search
    document.getElementById('filter-category').addEventListener('change', () => {
        currentPage = 1;
        updateIncidentsTable();
    });

    let searchTimeout = null;
    document.getElementById('filter-search').addEventListener('input', () => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            currentPage = 1;
            updateIncidentsTable();
        }, 300);
    });

    // Refresh Button Manual
    document.getElementById('btn-refresh').addEventListener('click', () => {
        const icon = document.getElementById('refresh-icon');
        icon.classList.add('animate-spin');
        Promise.all([updateMetrics(), updateIncidentsTable(), window.refreshBlockedIps()]).finally(() => {
            setTimeout(() => icon.classList.remove('animate-spin'), 600);
        });
    });

    // Clear / Reset Logs Button
    const btnClearLogs = document.getElementById('btn-clear-logs');
    if (btnClearLogs) {
        btnClearLogs.addEventListener('click', async () => {
            if (confirm("Apakah Anda yakin ingin mereset dan mengosongkan seluruh log insiden serta metrik pengujian?")) {
                try {
                    const res = await fetch('/api/incidents/clear', { method: 'POST' });
                    if (res.ok) {
                        cachedIncidents = {};
                        await updateMetrics();
                        await updateIncidentsTable();
                    }
                } catch (e) {
                    console.error('Gagal mereset log:', e);
                }
            }
        });
    }

    // Close Modal on Backdrop Click or Escape
    const modalEl = document.getElementById('incident-modal');
    modalEl.addEventListener('click', (e) => {
        if (e.target === modalEl) {
            closeIncidentModal();
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            closeIncidentModal();
        }
    });
});
