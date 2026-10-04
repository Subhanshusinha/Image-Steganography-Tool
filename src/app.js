// ══════════════════════════════════════════════════════
// StealthGuard — app.js
// ══════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {

    const stego = new Steganography();

    // ── Shared state ──────────────────────────────────
    let encodeImageData = null;
    let encodeMaxBytes  = 0;
    let encodeFileData  = null;
    let decodeImageData = null;
    let diffOrigData    = null;
    let diffEncData     = null;
    let isFileMode      = false;

    // ── Section routing ───────────────────────────────
    const ALL_SECTIONS = ['dashboard', 'encode', 'decode', 'analysis', 'security', 'guide'];

    function showSection(name) {
        // Hide all sections cleanly using style instead of class to avoid hidden+flex conflict
        ALL_SECTIONS.forEach(s => {
            const el = document.getElementById(s + '-section');
            if (el) el.style.display = 'none';
        });

        document.querySelectorAll('.sidebar-nav-btn').forEach(btn => {
            if (btn.dataset.section === name) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });

        const target = document.getElementById(name + '-section');
        if (target) {
            target.style.display = 'flex';
            target.classList.add('fade-in-up');
            window.scrollTo({ top: 0, behavior: 'instant' });
            setTimeout(() => target.classList.remove('fade-in-up'), 700);
        }

        if (name === 'dashboard') refreshStats();
    }

    // Sidebar nav clicks (desktop + mobile bottom nav)
    document.querySelectorAll('.sidebar-nav-btn').forEach(btn => {
        btn.addEventListener('click', () => showSection(btn.dataset.section));
    });

    // Hero / Action buttons
    document.querySelectorAll('.action-hero-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            if (btn.dataset.action) showSection(btn.dataset.action);
        });
    });

    // ── Stats ─────────────────────────────────────────
    function refreshStats() {
        const enc   = parseInt(localStorage.getItem('steg_enc')   || '0');
        const dec   = parseInt(localStorage.getItem('steg_dec')   || '0');
        const bytes = parseInt(localStorage.getItem('steg_bytes') || '0');

        const elEnc   = document.getElementById('stat-encryptions');
        const elDec   = document.getElementById('stat-decryptions');
        const elBytes = document.getElementById('stat-bytes');

        if (elEnc) elEnc.textContent = enc;
        if (elDec) elDec.textContent = dec;

        let bStr = bytes + ' B';
        if (bytes > 1048576) bStr = (bytes / 1048576).toFixed(2) + ' MB';
        else if (bytes > 1024) bStr = (bytes / 1024).toFixed(2) + ' KB';

        if (elBytes) elBytes.textContent = bStr + ' Processed';
    }
    refreshStats();

    // ── Activity log ─────────────────────────────────
    function logActivity(op, payload, status) {
        const tbody = document.getElementById('activity-log');
        if (!tbody) return;

        const placeholder = tbody.querySelector('[colspan]');
        if (placeholder) placeholder.parentElement.remove();

        const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const isOk = status === 'success';

        const tr = document.createElement('tr');
        tr.className = 'hover:bg-slate-50/80 transition-colors fade-in-up';
        tr.innerHTML = `
            <td class="px-4 py-3 font-medium">
                <span class="inline-block px-2.5 py-1 rounded-md text-[11px] bg-slate-100 text-slate-700 font-bold">${op}</span>
            </td>
            <td class="px-4 py-3 text-slate-500 font-mono text-xs truncate max-w-[120px]" title="${payload}">${payload}</td>
            <td class="px-4 py-3 text-slate-400 text-xs hidden sm:table-cell">${time}</td>
            <td class="px-4 py-3 text-right">
                <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold ${isOk ? 'bg-emerald-50 text-emerald-700' : 'bg-rose-50 text-rose-700'}">
                    ${isOk ? '✓ OK' : '✕ Failed'}
                </span>
            </td>`;
        tbody.insertBefore(tr, tbody.firstChild);
        while (tbody.children.length > 6) tbody.removeChild(tbody.lastChild);
    }

    // ── Generic dropzone setup (PNG only for steganography) ──
    function makeDropzone(zone, onFile) {
        if (!zone) return;
        zone.addEventListener('click', () => {
            const inp = document.createElement('input');
            inp.type   = 'file';
            inp.accept = 'image/png'; // PNG only — JPEG is lossy and destroys hidden data
            inp.onchange = e => { if (e.target.files[0]) onFile(e.target.files[0]); };
            inp.click();
        });
        zone.addEventListener('dragover',  e => { e.preventDefault(); zone.classList.add('border-indigo-400', 'bg-indigo-50/50'); });
        zone.addEventListener('dragleave', e => { e.preventDefault(); zone.classList.remove('border-indigo-400', 'bg-indigo-50/50'); });
        zone.addEventListener('drop', e => {
            e.preventDefault();
            zone.classList.remove('border-indigo-400', 'bg-indigo-50/50');
            const file = e.dataTransfer.files[0];
            if (!file) return;
            if (file.type !== 'image/png') {
                alert('Please use PNG images only. JPEG compression destroys hidden data.');
                return;
            }
            onFile(file);
        });
    }

    function loadImageToCanvas(file, canvas, onData) {
        const reader = new FileReader();
        reader.onload = ev => {
            const img = new Image();
            img.onload = () => {
                canvas.width  = img.width;
                canvas.height = img.height;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(img, 0, 0);
                onData(ctx.getImageData(0, 0, img.width, img.height));
            };
            img.src = ev.target.result;
        };
        reader.readAsDataURL(file);
    }

    // ── Capacity UI ───────────────────────────────────
    function updateCapacity() {
        if (!encodeImageData) return;
        let payloadSize = 0;
        if (isFileMode && encodeFileData) {
            payloadSize = encodeFileData.length;
        } else {
            const txt = document.getElementById('secret-message')?.value || '';
            payloadSize = new TextEncoder().encode(txt).length;
        }
        const overhead  = 11 + 44; // header + AES overhead estimate
        const totalUsed = payloadSize + overhead;
        const pct       = Math.min(100, (totalUsed / encodeMaxBytes) * 100);
        const bar       = document.getElementById('capacity-bar');
        const label     = document.getElementById('capacity-label');
        if (bar) {
            bar.style.width = pct + '%';
            bar.className   = `h-full rounded-full transition-all duration-300 ${pct > 90 ? 'bg-rose-500' : pct > 65 ? 'bg-amber-500' : 'bg-gradient-to-r from-indigo-500 to-purple-500'}`;
        }
        if (label) {
            label.textContent = `${totalUsed.toLocaleString()} / ${encodeMaxBytes.toLocaleString()} B`;
            label.className   = `text-xs font-bold ${pct > 90 ? 'text-rose-600' : 'text-indigo-600'}`;
        }
    }

    // ── ENCODE section ────────────────────────────────
    const encodeDropzone = document.getElementById('encode-dropzone');
    const encodePreview  = document.getElementById('encode-preview');
    const encodeCanvas   = document.getElementById('encode-canvas');

    makeDropzone(encodeDropzone, file => {
        loadImageToCanvas(file, encodeCanvas, data => {
            encodeImageData = data;
            encodeMaxBytes  = Math.floor(data.data.length / 8) - 11;
            encodeDropzone.style.display  = 'none';
            encodePreview.style.display   = 'flex';
            updateCapacity();
        });
    });

    document.getElementById('encode-remove-btn')?.addEventListener('click', () => {
        encodeImageData = null; encodeMaxBytes = 0; encodeFileData = null;
        encodePreview.style.display  = 'none';
        encodeDropzone.style.display = 'flex';
        document.getElementById('encode-result').style.display = 'none';
        updateCapacity();
    });

    const typeTextBtn = document.getElementById('type-text-btn');
    const typeFileBtn = document.getElementById('type-file-btn');

    function setPayloadMode(mode) {
        isFileMode = mode === 'file';
        document.getElementById('text-payload-container').classList.toggle('hidden',  isFileMode);
        document.getElementById('file-payload-container').classList.toggle('hidden', !isFileMode);
        if (typeTextBtn && typeFileBtn) {
            typeTextBtn.className = `px-4 py-1.5 text-xs font-bold rounded-md transition-all ${!isFileMode ? 'bg-white shadow-sm text-indigo-700' : 'text-slate-500 hover:text-slate-800'}`;
            typeFileBtn.className = `px-4 py-1.5 text-xs font-bold rounded-md transition-all ${ isFileMode ? 'bg-white shadow-sm text-indigo-700' : 'text-slate-500 hover:text-slate-800'}`;
        }
        updateCapacity();
    }

    typeTextBtn?.addEventListener('click', () => setPayloadMode('text'));
    typeFileBtn?.addEventListener('click', () => setPayloadMode('file'));

    document.getElementById('secret-file')?.addEventListener('change', e => {
        const file = e.target.files[0];
        if (!file) { encodeFileData = null; return; }
        document.getElementById('file-chosen-name').textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
        const reader = new FileReader();
        reader.onload = ev => {
            encodeFileData = new Uint8Array(ev.target.result);
            updateCapacity();
        };
        reader.readAsArrayBuffer(file);
    });

    document.getElementById('secret-message')?.addEventListener('input', updateCapacity);
    document.getElementById('encode-password')?.addEventListener('input', updateCapacity);

    document.getElementById('encode-btn')?.addEventListener('click', async () => {
        if (!encodeImageData) { alert('Please upload a cover image first.'); return; }

        let payloadBytes, metadata;
        if (isFileMode) {
            if (!encodeFileData) { alert('Please select a file to hide.'); return; }
            payloadBytes = encodeFileData;
            const secretFileInput = document.getElementById('secret-file');
            metadata = { type: 'file', name: secretFileInput.files[0].name, mime: secretFileInput.files[0].type || 'application/octet-stream' };
        } else {
            const msg = document.getElementById('secret-message').value.trim();
            if (!msg) { alert('Please enter a secret message.'); return; }
            payloadBytes = new TextEncoder().encode(msg);
            metadata = { type: 'text' };
        }

        const password = document.getElementById('encode-password').value || null;
        const btn = document.getElementById('encode-btn');
        btn.disabled = true;
        btn.innerHTML = `<svg class="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"></path></svg> Processing...`;

        try {
            const resultData = await stego.encode(encodeImageData, payloadBytes, metadata, password);
            const rc = document.getElementById('encode-result-canvas');
            rc.width  = resultData.width;
            rc.height = resultData.height;
            rc.getContext('2d').putImageData(resultData, 0, 0);

            document.getElementById('encode-result').style.display = 'flex';
            logActivity('Hide Data', metadata.type === 'file' ? metadata.name : 'Text Message', 'success');
            refreshStats();
        } catch(err) {
            alert('Error: ' + err.message);
            logActivity('Hide Data', 'failed', 'error');
        } finally {
            btn.disabled = false;
            btn.innerHTML = `<svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg> Encrypt & Embed`;
        }
    });

    document.getElementById('close-result-btn')?.addEventListener('click', () => {
        document.getElementById('encode-result').style.display = 'none';
    });

    document.getElementById('download-btn')?.addEventListener('click', () => {
        const rc = document.getElementById('encode-result-canvas');
        const a  = document.createElement('a');
        a.download = 'stealthguard-encoded.png';
        a.href     = rc.toDataURL('image/png');
        a.click();
    });

    // ── DECODE section ────────────────────────────────
    const decodeDropzone = document.getElementById('decode-dropzone');
    const decodePreview  = document.getElementById('decode-preview');
    const decodeCanvas   = document.getElementById('decode-canvas');

    makeDropzone(decodeDropzone, file => {
        loadImageToCanvas(file, decodeCanvas, data => {
            decodeImageData = data;
            decodeDropzone.style.display = 'none';
            decodePreview.style.display  = 'flex';
        });
    });

    document.getElementById('decode-remove-btn')?.addEventListener('click', () => {
        decodeImageData = null;
        decodePreview.style.display  = 'none';
        decodeDropzone.style.display = 'flex';
        document.getElementById('decode-result').style.display = 'none';
    });

    document.getElementById('decode-btn')?.addEventListener('click', async () => {
        if (!decodeImageData) { alert('Please upload an image first.'); return; }

        const password = document.getElementById('decode-password').value || null;
        const btn = document.getElementById('decode-btn');
        btn.disabled    = true;
        btn.textContent = 'Extracting...';

        try {
            const result = await stego.decode(decodeImageData, password);
            const msgEl  = document.getElementById('extracted-message');
            const actionBtn = document.getElementById('copy-or-download-btn');

            if (result.type === 'text') {
                msgEl.textContent      = result.data;
                actionBtn.textContent  = 'Copy to Clipboard';
                actionBtn.onclick = () => {
                    navigator.clipboard.writeText(result.data).catch(() => {});
                    actionBtn.textContent = 'Copied!';
                    setTimeout(() => actionBtn.textContent = 'Copy to Clipboard', 2000);
                };
                logActivity('Extract Data', 'Text Message', 'success');
            } else {
                msgEl.textContent = `File Extracted\n\nName: ${result.name}\nSize: ${result.data.length.toLocaleString()} bytes\nType: ${result.mime}`;
                actionBtn.textContent = `Download File`;
                actionBtn.onclick = () => {
                    const blob = new Blob([result.data], { type: result.mime });
                    const url  = URL.createObjectURL(blob);
                    const a    = document.createElement('a');
                    a.href = url; a.download = result.name; a.click();
                    URL.revokeObjectURL(url);
                };
                logActivity('Extract Data', result.name, 'success');
            }

            document.getElementById('decode-result').style.display = 'flex';
            
            refreshStats();
        } catch(err) {
            alert('Error: ' + err.message);
            logActivity('Extract Data', 'failed', 'error');
        } finally {
            btn.disabled    = false;
            btn.textContent = 'Extract Payload';
        }
    });

    // ── DIFF ANALYSIS section ─────────────────────────
    function loadDiffImage(file, canvas, placeholderId, onData) {
        document.getElementById(placeholderId).classList.add('hidden');
        loadImageToCanvas(file, canvas, data => {
            canvas.classList.remove('hidden');
            onData(data);
        });
    }

    document.getElementById('diff-orig-file')?.addEventListener('change', e => {
        if (e.target.files[0]) loadDiffImage(e.target.files[0], document.getElementById('diff-orig-canvas'), 'diff-orig-placeholder', d => diffOrigData = d);
    });
    document.getElementById('diff-enc-file')?.addEventListener('change', e => {
        if (e.target.files[0]) loadDiffImage(e.target.files[0], document.getElementById('diff-enc-canvas'), 'diff-enc-placeholder', d => diffEncData = d);
    });

    document.getElementById('run-diff-btn')?.addEventListener('click', () => {
        if (!diffOrigData || !diffEncData) { alert('Please upload both images first.'); return; }
        if (diffOrigData.width !== diffEncData.width || diffOrigData.height !== diffEncData.height) {
            alert('Images must have identical dimensions for comparison.'); return;
        }

        const dc = document.getElementById('diff-canvas');
        dc.width  = diffOrigData.width;
        dc.height = diffOrigData.height;
        const ctx    = dc.getContext('2d');
        const outImg = ctx.createImageData(dc.width, dc.height);
        let changed  = 0;

        for (let i = 0; i < diffOrigData.data.length; i += 4) {
            const dr = Math.abs(diffOrigData.data[i]   - diffEncData.data[i]);
            const dg = Math.abs(diffOrigData.data[i+1] - diffEncData.data[i+1]);
            const db = Math.abs(diffOrigData.data[i+2] - diffEncData.data[i+2]);

            if (dr > 0 || dg > 0 || db > 0) {
                outImg.data[i]   = 255;
                outImg.data[i+1] = 30;
                outImg.data[i+2] = 50;
                outImg.data[i+3] = 255;
                changed++;
            } else {
                outImg.data[i]   = Math.round(diffOrigData.data[i]   * 0.12);
                outImg.data[i+1] = Math.round(diffOrigData.data[i+1] * 0.12);
                outImg.data[i+2] = Math.round(diffOrigData.data[i+2] * 0.12);
                outImg.data[i+3] = 255;
            }
        }
        ctx.putImageData(outImg, 0, 0);
        const total = diffOrigData.width * diffOrigData.height;
        document.getElementById('diff-count-label').textContent =
            `${changed.toLocaleString()} modified pixels out of ${total.toLocaleString()} total (${((changed / total) * 100).toFixed(4)}%)`;
        document.getElementById('diff-result').classList.remove('hidden');
        logActivity('Diff Analysis', `${changed} pixels changed`, 'success');
    });

    // ── Real-Time Clock ───────────────────────────────
    function updateClock() {
        const el = document.getElementById('clock-time');
        if (el) {
            const now = new Date();
            el.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }
    }
    setInterval(updateClock, 1000);
    updateClock();

    // ── Initial state ─────────────────────────────────
    showSection('dashboard');
});
