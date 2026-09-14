const ICONS = {
    pirate:      { ship: ['⛵', '🚢', '🛳️'], island: '🏝️', globe: '🌍', threat: '☠', inbox: '📥', clean: '✅', unscanned: '⏳', pend: '⏳', scan: '⚔', pick: '⚲', peers: '⚡' },
    'cherry-blossom': { ship: ['🌸', '🌺', '🏵️'], island: '🍃', globe: '💮', threat: '🥀', inbox: '🌱', clean: '🌸', unscanned: '🌷', pend: '⏳', scan: '⚘', pick: '⚲', peers: '🌸' },
    neon:        { ship: ['⛵', '🚢', '🛳️'], island: '🏝️', globe: '🌍', threat: '☠', inbox: '📥', clean: '✅', unscanned: '⏳', pend: '⏳', scan: '⚔', pick: '⚲', peers: '⚡' },
    '/home':     { ship: ['💾', '🖥️', '🗄️'], island: '📁', globe: '💿', threat: '☠', inbox: '💽', clean: '✅', unscanned: '⏳', pend: '⏳', scan: '⚔', pick: '⚲', peers: '⚡' },
    coffee:      { ship: ['☕', '🫖', '🍵'], island: '🍩', globe: '🍪', threat: '☠', inbox: '🥛', clean: '🍰', unscanned: '🌰', pend: '⏳', scan: '⚔', pick: '⚲', peers: '⚡' },
};
const THEMEKEY = { 'pirate': 'pirate', 'Cherry Blossom': 'cherry-blossom', 'neon': 'neon', '/Home': '/home', 'coffee': 'coffee' };

function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function fmtBytes(b) {
    if (!b || b <= 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(b) / Math.log(k));
    return parseFloat((b / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function fmtRate(b) {
    return fmtBytes(b) + '/s';
}

function fmtTime(ts) {
    const d = new Date(ts);
    if (isNaN(d)) return '';
    const p = (n) => String(n).padStart(2, '0');
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
}

function truncate(s, n) {
    if (s.length <= n) return s;
    if (n <= 3) return s.slice(0, n);
    return s.slice(0, n - 3) + '...';
}

function padLeft(s, n) {
    s = String(s);
    return s.length >= n ? s : ' '.repeat(n - s.length) + s;
}

function app() {
    return {
        webTheme: 'pirate',
        page: 'downloads',
        torrents: [],
        selected: 0,
        history: [],
        historySel: 0,
        historyFocus: '',
        historyReportOff: 0,
        vpn: { connected: false, interface: '', ip_address: '', reason: '' },
        engines: { clamav: false, yara: false, sandbox: false },
        panic: false,
        err: '',
        sections: [],
        settingsOpen: false,
        settingsCursor: 0,
        inputMode: false,
        inputValue: '',
        askReferrer: false,
        referrerInput: '',
        pendingURL: '',
        addOpen: false,
        addValue: '',
        addFile: null,
        addReferrer: false,
        picking: null,
        pending: {},
        pickCursor: 0,
        filesOpen: false,
        filesCursor: 0,
        windowW: typeof window !== 'undefined' ? window.innerWidth : 0,
        rescanning: null,
        rescanStatus: { running: false, step: '', files: [] },
        ws: null,
        timers: [],

        init() {
            this.fetchData();
            this.fetchVPN();
            this.fetchEngines();
            this.fetchSettings();
            this.fetchStatus();
            this.connectWS();
            this.timers.push(setInterval(() => this.fetchData(), 2000));
            this.timers.push(setInterval(() => { this.fetchVPN(); this.fetchStatus(); }, 2000));
            this.timers.push(setInterval(() => this.fetchEngines(), 5000));
            this.timers.push(setInterval(() => {
                if (this.page === 'history' && this.historyFocus !== 'report') this.fetchHistory();
            }, 2500));
            this.timers.push(setInterval(() => {
                if (this.rescanning) this.tickRescan();
            }, 1000));
            document.addEventListener('visibilitychange', () => {
                if (!document.hidden) { this.fetchData(); this.fetchVPN(); this.fetchStatus(); this.fetchEngines(); }
            });
            window.addEventListener('resize', () => { this.windowW = window.innerWidth; });
        },

        icons() { return ICONS[this.webTheme] || ICONS.pirate; },

        async fetchData() {
            try {
                const res = await fetch('/api/torrents');
                if (!res.ok) return;
                this.torrents = await res.json();
                if (this.selected >= this.torrents.length) this.selected = Math.max(0, this.torrents.length - 1);
                this.maybeOpenPicker();
            } catch (e) { this.err = String(e); }
        },

        async fetchHistory() {
            try {
                const res = await fetch('/api/history');
                if (!res.ok) return;
                this.history = await res.json();
                if (this.historySel >= this.history.length) this.historySel = Math.max(0, this.history.length - 1);
            } catch (e) { this.err = String(e); }
        },

        async fetchVPN() {
            try {
                const res = await fetch('/api/vpn');
                if (!res.ok) return;
                this.vpn = await res.json();
            } catch (e) { /* quiet */ }
        },

        async fetchStatus() {
            try {
                const res = await fetch('/api/status');
                if (!res.ok) return;
                const st = await res.json();
                if (typeof st.panicked === 'boolean') this.panic = st.panicked;
            } catch (e) { /* quiet */ }
        },

        async fetchEngines() {
            try {
                const res = await fetch('/api/engines');
                if (!res.ok) return;
                this.engines = await res.json();
            } catch (e) { /* quiet */ }
        },

        async fetchSettings() {
            try {
                const res = await fetch('/api/settings');
                if (!res.ok) return;
                this.sections = await res.json();
                this.applyTheme();
            } catch (e) { /* quiet */ }
        },

        applyTheme() {
            for (const sec of this.sections) {
                for (const s of sec.settings) {
                    if (s.key === 'theme') {
                        this.webTheme = THEMEKEY[s.value] || 'pirate';
                        return;
                    }
                }
            }
        },

        connectWS() {
            const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
            this.ws = new WebSocket(`${protocol}//${location.host}/ws`);
            this.ws.onmessage = (e) => {
                try { this.handleEvent(JSON.parse(e.data)); } catch (err) { /* quiet */ }
            };
            this.ws.onclose = () => {
                if (this.ws) setTimeout(() => this.connectWS(), 3000);
            };
        },

        handleEvent(msg) {
            switch (msg.type) {
                case 'torrent.progress':
                case 'torrent.added':
                case 'torrent.complete':
                case 'torrent.cancelled':
                case 'torrent.paused':
                case 'torrent.resumed':
                case 'torrent.scanning':
                    this.updateTorrent(msg.data);
                    break;
                case 'scan.clean':
                    this.updateTorrentScan(msg.data.id, 'clean');
                    break;
                case 'scan.threat':
                    this.updateTorrentScan(msg.data.torrent_id, 'threats_found');
                    break;
                case 'scan.quarantined':
                    this.updateTorrentState(msg.data.id, 'quarantined');
                    break;
                case 'scan.complete':
                    if (this.rescanning === msg.data.id) {
                        this.rescanStatus.running = false;
                        this.rescanning = null;
                        this.fetchHistory();
                        this.fetchData();
                    }
                    break;
                case 'vpn.panic':
                    this.panic = true;
                    break;
                case 'vpn.recovered':
                    this.panic = false;
                    break;
            }
        },

        updateTorrent(torrent) {
            const idx = this.torrents.findIndex(t => t.id === torrent.id);
            if (idx >= 0) this.torrents[idx] = { ...this.torrents[idx], ...torrent };
            else this.torrents.push(torrent);
        },

        updateTorrentScan(id, result) {
            const t = this.torrents.find(t => t.id === id);
            if (t) t.scan_result = result;
        },

        updateTorrentState(id, state) {
            const t = this.torrents.find(t => t.id === id);
            if (t) t.state = state;
        },

        onKey(e) {
            if (e.metaKey || e.ctrlKey || e.altKey) return;
            if (e.target && e.target.closest && e.target.closest('.addpop')) {
                if (e.key === 'Escape') {
                    e.preventDefault();
                    if (this.addReferrer) this.addReferrer = false;
                    else this.closeAdd();
                }
                return;
            }
            if (this.addOpen) { this.onAddKey(e); return; }
            if (this.settingsOpen) { this.onSettingsKey(e); return; }
            if (this.picking) { this.onPickerKey(e); return; }
            if (this.page === 'downloads' && this.filesOpen) { this.onFilesKey(e); return; }
            this.onMainKey(e);
        },

        onAddKey(e) {
            if (e.key === 'Escape') {
                e.preventDefault();
                if (this.addReferrer) this.addReferrer = false;
                else this.closeAdd();
            } else if (e.key === 'Enter') {
                e.preventDefault();
                this.addSubmit();
            }
        },

        onSettingsKey(e) {
            switch (e.key) {
                case 'Escape': case 'q': case 'Q': this.settingsOpen = false; break;
                case 'ArrowDown': case 'j': case 'J': this.settingsMove(1); break;
                case 'ArrowUp': case 'k': case 'K': this.settingsMove(-1); break;
                case 'Enter': case ' ': case 'l': case 'r': this.cycleSettingAtCursor(); break;
            }
            e.preventDefault();
        },

        onPickerKey(e) {
            switch (e.key) {
                case 'Escape': this.closePicker(); break;
                case 'Enter': this.confirmSelection(); break;
                case ' ': this.toggleFileAtCursor(); break;
                case 'l': case 'L': this.takeAll(); break;
                case 'u': case 'U': this.takeNone(); break;
                case 'j': case 'J': case 'ArrowDown': this.pickMove(1); break;
                case 'k': case 'K': case 'ArrowUp': this.pickMove(-1); break;
            }
            e.preventDefault();
        },

        onFilesKey(e) {
            if (e.key === 'Enter' || e.key === 'Escape' || e.key === 'q' || e.key === 'Q') {
                this.filesOpen = false;
                this.filesCursor = 0;
            } else if (e.key === 'ArrowDown' || e.key === 'j' || e.key === 'J' ||
                       e.key === 'ArrowUp' || e.key === 'k' || e.key === 'K') {
                this.filesScroll(e.key === 'ArrowUp' || e.key === 'k' || e.key === 'K' ? -1 : 1);
            }
            e.preventDefault();
        },

        onMainKey(e) {
            switch (e.key) {
                case 'ArrowDown':
                    if (this.page === 'history' && this.historyFocus === 'report') this.reportScroll(1);
                    else this.nextPage();
                    e.preventDefault();
                    break;
                case 'ArrowUp':
                    if (this.page === 'history' && this.historyFocus === 'report') this.reportScroll(-1);
                    else this.prevPage();
                    e.preventDefault();
                    break;
                case 'ArrowRight':
                    if (this.page === 'history') this.nextPage();
                    break;
                case 'ArrowLeft':
                    if (this.page === 'history') this.prevPage();
                    break;
                case 'j': case 'J': this.navDown(); e.preventDefault(); break;
                case 'k': case 'K': this.navUp(); e.preventDefault(); break;
                case 'a': case 'A': this.startInput(); break;
                case 'p': case 'P': if (this.page === 'downloads') this.pauseResume(); break;
                case 'x': case 'X':
                    if (this.page === 'history') this.deleteHistory();
                    else this.deleteTorrent();
                    break;
                case 't': case 'T': this.toggleSettings(); break;
                case 'r': case 'R': if (this.page === 'history') this.rescanEntry(); break;
                case 's': case 'S': if (this.page === 'history') this.toggleSeed(); break;
                case 'o': case 'O': if (this.page === 'history') this.openEntry(); break;
                case 'Enter':
                    if (this.page === 'history' && this.historyFocus !== 'report') this.openEntry();
                    else if (this.page === 'downloads') this.toggleFiles();
                    break;
                case 'g': case 'G':
                    if (this.page === 'history') this.fetchHistory();
                    else this.togglePanic();
                    break;
                case ' ': if (this.page === 'downloads') this.togglePanic(); break;
            }
        },

        navDown() {
            if (this.page === 'history' && this.historyFocus === 'report') {
                if (this.historyReportOff < this.reportLines().length - 1) this.historyReportOff++;
                return;
            }
            if (this.page === 'history') {
                if (this.historySel < this.history.length - 1) {
                    this.historySel++;
                    this.scrollEl('histrow' + this.historySel);
                }
                return;
            }
            if (this.selected < this.torrents.length - 1) {
                this.selected++;
                this.scrollEl('torrow' + this.selected);
            }
        },

        navUp() {
            if (this.page === 'history' && this.historyFocus === 'report') {
                if (this.historyReportOff > 0) this.historyReportOff--;
                return;
            }
            if (this.page === 'history') {
                if (this.historySel > 0) {
                    this.historySel--;
                    this.scrollEl('histrow' + this.historySel);
                }
                return;
            }
            if (this.selected > 0) {
                this.selected--;
                this.scrollEl('torrow' + this.selected);
            }
        },

        reportScroll(d) {
            this.historyReportOff = Math.max(0, Math.min(this.reportLines().length - 1, this.historyReportOff + d));
        },

        nextPage() {
            if (this.page === 'downloads') {
                this.page = 'history';
                if (!this.history.length) this.fetchHistory();
                return;
            }
            if (this.page === 'history' && this.historyFocus !== 'report') {
                this.historyFocus = 'report';
                this.historyReportOff = 0;
            }
        },

        prevPage() {
            if (this.page === 'history' && this.historyFocus === 'report') {
                this.historyFocus = '';
                return;
            }
            this.page = 'downloads';
        },

        scrollEl(el) {
            this.$nextTick(() => {
                const elm = document.getElementById(el);
                if (elm) elm.scrollIntoView({ block: 'nearest' });
            });
        },

        startInput() {
            this.addOpen = true;
            this.addValue = '';
            this.addFile = null;
            this.addReferrer = false;
            this.referrerInput = '';
            this.pendingURL = '';
        },

        closeAdd() {
            this.addOpen = false;
            this.addValue = '';
            this.addFile = null;
            this.addReferrer = false;
            this.referrerInput = '';
            this.pendingURL = '';
        },

        pickTorrentFile() {
            if (this.$refs.fileInput) this.$refs.fileInput.click();
        },

        onFilePick(event) {
            const file = event.target.files[0];
            event.target.value = '';
            this.addFile = file || null;
            if (this.addOpen) {
                const el = this.addReferrer ? this.$refs.refinput : this.$refs.addinput;
                if (el) el.focus();
            }
        },

        async addSubmit() {
            if (this.addFile) {
                this.uploadTorrent(this.addFile);
                return;
            }
            const raw = (this.addValue || '').trim();
            if (this.addReferrer) {
                const url = this.pendingURL;
                const ref = (this.referrerInput || '').trim();
                this.closeAdd();
                this.addURL(url, ref);
                return;
            }
            if (!raw) return;
            if (this.isHTTPURL(raw)) {
                this.pendingURL = raw;
                this.addValue = '';
                this.addReferrer = true;
                this.referrerInput = '';
                return;
            }
            this.closeAdd();
            this.addAny(raw);
        },

        isHTTPURL(s) {
            return /^https?:\/\//i.test(s);
        },

        async addAny(raw) {
            this.err = '';
            const body = {};
            if (this.isHTTPURL(raw)) { body.url = raw; }
            else { body.magnet = raw; body.wait = true; }
            try {
                await fetch('/api/torrents', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                await this.fetchData();
            } catch (e) { this.err = String(e); }
        },

        async addURL(url, referrer) {
            this.err = '';
            try {
                await fetch('/api/torrents', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url, referrer })
                });
                await this.fetchData();
            } catch (e) { this.err = String(e); }
        },

        async uploadTorrent(src) {
            const file = src && src.target ? src.target.files[0] : src;
            if (src && src.target) src.target.value = '';
            if (!file) return;
            this.err = '';
            const form = new FormData();
            form.append('torrent', file);
            form.append('wait', 'true');
            try {
                await fetch('/api/torrents', { method: 'POST', body: form });
                await this.fetchData();
                this.closeAdd();
            } catch (e) { this.err = String(e); }
        },

        async pauseResume(t) {
            const tt = t || this.torrents[this.selected];
            if (!tt) return;
            const action = tt.state === 'paused' ? 'resume' : 'pause';
            this.err = '';
            try {
                await fetch(`/api/torrents/${tt.id}/${action}`, { method: 'POST' });
                await this.fetchData();
            } catch (e) { this.err = String(e); }
        },

        async resumeTorrent(t) {
            if (!t) return;
            this.err = '';
            try {
                await fetch(`/api/torrents/${t.id}/resume`, { method: 'POST' });
                await this.fetchData();
            } catch (e) { this.err = String(e); }
        },

        async pauseTorrent(t) {
            if (!t) return;
            this.err = '';
            try {
                await fetch(`/api/torrents/${t.id}/pause`, { method: 'POST' });
                await this.fetchData();
            } catch (e) { this.err = String(e); }
        },

        async deleteTorrent(t) {
            const tt = t || this.torrents[this.selected];
            if (!tt) return;
            if (!confirm('Cancel and remove this torrent?')) return;
            this.err = '';
            try {
                await fetch(`/api/torrents/${tt.id}`, { method: 'DELETE' });
                this.torrents = this.torrents.filter(x => x.id !== tt.id);
                if (this.selected >= this.torrents.length) this.selected = Math.max(0, this.torrents.length - 1);
            } catch (e) { this.err = String(e); }
        },

        async torrentFolder(t) {
            if (!t) return;
            this.err = '';
            try { await fetch(`/api/torrents/${t.id}/open`, { method: 'POST' }); }
            catch (e) { this.err = String(e); }
        },

        async deleteHistory() {
            const e = this.history[this.historySel];
            if (!e) return;
            if (!confirm('Delete this previous download from disk?')) return;
            this.err = '';
            try {
                await fetch(`/api/history/${e.id}/delete`, { method: 'POST' });
                await this.fetchHistory();
            } catch (err) { this.err = String(err); }
        },

        async openEntry() {
            const e = this.history[this.historySel];
            if (!e) return;
            try { await fetch(`/api/history/${e.id}/open`, { method: 'POST' }); }
            catch (err) { this.err = String(err); }
        },

        async rescanEntry() {
            const e = this.history[this.historySel];
            if (!e || !e.infohash) {
                this.err = 'no infohash recorded for this download — cannot re-scan';
                return;
            }
            if (this.rescanning) return;
            this.err = '';
            this.rescanning = e.infohash;
            this.rescanStatus = { running: true, step: '', files: [] };
            try { await fetch(`/api/history/${e.infohash}/rescan`, { method: 'POST' }); }
            catch (err) {
                this.rescanning = null;
                this.err = String(err);
            }
        },

        async toggleSeed() {
            const e = this.history[this.historySel];
            if (!e) return;
            if (!e.seedable) {
                this.err = 'this download carries no torrent metadata — URL downloads cannot be re-seeded';
                return;
            }
            this.err = '';
            try {
                await fetch(`/api/history/${e.infohash}/seed`, { method: 'POST' });
                await this.fetchHistory();
            } catch (err) { this.err = String(err); }
        },

        async tickRescan() {
            const id = this.rescanning;
            if (!id) return;
            try {
                const res = await fetch(`/api/history/${id}/rescan`);
                if (!res.ok) return;
                const st = await res.json();
                if (this.rescanning === id) this.rescanStatus = st;
                if (!st.running) {
                    this.rescanning = null;
                    await this.fetchHistory();
                    this.fetchData();
                }
            } catch (e) { /* quiet */ }
        },

        reportLines() {
            if (this.history.length === 0) return [];
            const e = this.history[this.historySel];
            if (this.rescanning && e.infohash === this.rescanning) return this.liveLines();
            return this.renderReportLines(e);
        },

        liveLines() {
            const out = [];
            if (this.rescanStatus.step) out.push('⚔ ' + this.rescanStatus.step + ' ⚔');
            const files = this.rescanStatus.files || [];
            if (!files.length) { out.push('Preparing scan...'); return out; }
            for (const f of files) {
                let s = '✅ ' + (f.path.split('/').pop() || f.path);
                if (f.result === 'threat') s = '☠ ' + (f.path.split('/').pop() || f.path) + ' - ' + (f.threat || '');
                else if (f.result === 'unscanned') s = '⚠ ' + (f.path.split('/').pop() || f.path) + (f.error ? ' - ' + f.error : '');
                out.push(s);
            }
            return out.slice(-40);
        },

        renderReportLines(e) {
            const out = [];
            out.push('Torrent: ' + e.name);
            out.push('Destination: [' + e.root + ']');
            out.push('Size:        ' + fmtBytes(e.size));
            out.push('Files:       ' + e.files);
            out.push('Modified:    ' + fmtTime(e.mod_time));
            if (e.report) {
                out.push('Scan results:');
                for (const ln of e.report.split('\n')) out.push(ln);
            } else {
                out.push('No scan report for this download.');
            }
            return out;
        },

        reportHtml() {
            if (this.history.length === 0) return '';
            const e = this.history[this.historySel];
            if (this.rescanning && e.infohash === this.rescanning) return this.rescanHtml();
            return this.renderReportLines(e).map(esc).join('<br>');
        },

        rescanHtml() {
            const ic = this.icons();
            const out = [];
            if (this.rescanStatus.step) out.push('<span class="c-unscanned">' + esc(ic.scan + ' ' + this.rescanStatus.step + ' ' + ic.scan) + '</span>');
            const files = this.rescanStatus.files || [];
            if (!files.length) { out.push('<span class="c-label">Preparing scan...</span>'); }
            for (const f of files) {
                const base = f.path.split('/').pop() || f.path;
                if (f.result === 'threat') {
                    out.push('<span class="c-threat">' + esc(ic.threat + ' ' + base) + (f.threat ? ' - ' + esc(f.threat) : '') + '</span>');
                } else if (f.result === 'unscanned') {
                    out.push('<span class="c-unscanned">⚠ ' + esc(base) + (f.error ? ' - ' + esc(f.error) : '') + '</span>');
                } else {
                    out.push('<span class="c-clean">' + esc(ic.clean + ' ' + base) + '</span>');
                }
            }
            return out.slice(-40).join('<br>');
        },

        reportTitle() {
            const e = this.history[this.historySel];
            if (!e) return '';
            if (this.rescanning && e.infohash === this.rescanning) return ' LIVE RESCAN — ' + truncate(e.name, 40) + ' ';
            return ' SCAN REPORT — ' + truncate(e.name, 40) + ' ';
        },

        reportVis() {
            return Math.max(8, Math.floor((window.innerHeight - 260) / 20));
        },

        reportPaneHtml() {
            const L = this.reportLines();
            const vis = this.reportVis();
            let off = this.historyReportOff;
            if (off > L.length - vis) off = Math.max(0, L.length - vis);
            if (off < 0) off = 0;
            return L.slice(off, off + vis).join('\n');
        },

        scrollInfoHtml() {
            const L = this.reportLines();
            const vis = this.reportVis();
            const off = this.historyReportOff > L.length - vis ? Math.max(0, L.length - vis) : Math.max(0, this.historyReportOff);
            if (L.length <= vis) return '';
            return ' report [' + (off + 1) + '-' + Math.min(off + vis, L.length) + '/' + L.length + '] ';
        },

        toggleSettings() {
            this.settingsOpen = !this.settingsOpen;
            if (this.settingsOpen && !this.sections.length) this.fetchSettings();
        },

        settingKeys() {
            const keys = [];
            for (const sec of this.sections) for (const s of sec.settings) keys.push(s.key);
            return keys;
        },

        settingsMove(d) {
            const n = this.settingKeys().length;
            if (!n) return;
            this.settingsCursor = (this.settingsCursor + d + n) % n;
        },

        cycleSettingAtCursor() {
            const keys = this.settingKeys();
            const k = keys[this.settingsCursor];
            if (k) this.cycleSetting(k);
        },

        settingsNdx(sec, s) {
            let i = 0;
            for (const sec2 of this.sections) {
                for (const s2 of sec2.settings) {
                    if (sec2 === sec && s2 === s) return i;
                    i++;
                }
            }
            return 0;
        },

        padTo(s, n) {
            s = String(s);
            return s.length >= n ? s : s + ' '.repeat(n - s.length);
        },

        async cycleSetting(key) {
            this.err = '';
            try {
                const res = await fetch('/api/settings/cycle', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ key })
                });
                if (!res.ok) return;
                this.sections = await res.json();
                this.applyTheme();
            } catch (e) { this.err = String(e); }
        },

        maybeOpenPicker() {
            if (this.picking || this.addOpen || this.settingsOpen || this.page !== 'downloads') return;
            const t = this.torrents.find(x => x.awaiting_selection && x.files && x.files.length);
            if (!t) return;
            if (t.files.length === 1) {
                this.autoSelectAll(t);
                return;
            }
            this.openPicker(t);
        },

        async autoSelectAll(t) {
            this.err = '';
            try {
                await fetch(`/api/torrents/${t.id}/select`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ files: [] })
                });
                await this.fetchData();
            } catch (e) { this.err = String(e); }
        },

        openPicker(t) {
            const pre = {};
            for (const p of t.selected_files || []) pre[p] = true;
            const sel = {};
            for (const f of t.files || []) {
                sel[f.path] = (t.selected_files && t.selected_files.length > 0) ? Boolean(pre[f.path]) : true;
            }
            this.picking = t.id;
            this.pending = sel;
            this.pickCursor = 0;
        },

        closePicker() {
            this.picking = null;
        },

        toggleFile(path) {
            this.pending[path] = !this.pending[path];
        },

        pickKeys() {
            return Object.keys(this.pending);
        },

        pickSel(path) {
            return this.pickKeys().indexOf(path) === this.pickCursor;
        },

        pickClick(path) {
            this.pickCursor = this.pickKeys().indexOf(path);
            this.toggleFile(path);
        },

        pickMove(d) {
            const n = this.pickKeys().length;
            if (!n) return;
            this.pickCursor = (this.pickCursor + d + n) % n;
            const rows = document.querySelectorAll('.picker-row');
            const elm = rows[this.pickCursor];
            if (elm) elm.scrollIntoView({ block: 'nearest' });
        },

        pickCursorPath() {
            return this.pickKeys()[this.pickCursor];
        },

        toggleFileAtCursor() {
            const p = this.pickCursorPath();
            if (p) this.toggleFile(p);
        },

        toggleFiles() {
            if (this.selected < 0 || this.selected >= this.torrents.length) return;
            if (!this.torrents[this.selected]) return;
            this.filesOpen = !this.filesOpen;
            this.filesCursor = 0;
        },

        clickCard(i) {
            if (this.selected === i) {
                this.toggleFiles();
                return;
            }
            this.selected = i;
            this.filesOpen = true;
            this.filesCursor = 0;
        },

        clickHistory(i) {
            this.historySel = i;
            this.historyFocus = 'report';
            this.historyReportOff = 0;
        },

        filesScroll(d) {
            const t = this.selected < this.torrents.length ? this.torrents[this.selected] : null;
            if (!t) return;
            const n = (t.files || []).length;
            if (!n) return;
            let c = this.filesCursor + d;
            if (c < 0) c = 0;
            if (c > n - 1) c = n - 1;
            this.filesCursor = c;
            this.$nextTick(() => {
                const box = document.getElementById('fbox' + this.selected);
                if (!box) return;
                const rows = box.querySelectorAll('.filebox-body .filebox-row');
                if (rows[c]) rows[c].scrollIntoView({ block: 'nearest' });
            });
        },

        fileMark(f) {
            if (f.scan_result === 'clean') return '✓';
            if (f.scan_result === 'threat') return '☠';
            return '◌';
        },

        takeAll() {
            for (const p in this.pending) this.pending[p] = true;
        },

        takeNone() {
            for (const p in this.pending) this.pending[p] = false;
        },

        pendingFiles() {
            return Object.keys(this.pending).filter(p => this.pending[p]);
        },

        async confirmSelection() {
            const id = this.picking;
            if (!id) return;
            this.err = '';
            this.picking = null;
            try {
                await fetch(`/api/torrents/${id}/select`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ files: this.pendingFiles() })
                });
            } catch (e) { this.err = String(e); }
            await this.fetchData();
        },

        async downloadAll() {
            const id = this.picking;
            if (!id) return;
            this.picking = null;
            this.err = '';
            try {
                await fetch(`/api/torrents/${id}/select`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ files: [] })
                });
            } catch (e) { this.err = String(e); }
            await this.fetchData();
        },

        async togglePanic() {
            if (!confirm('MANUAL PANIC: Stop all torrents?')) return;
            this.err = '';
            try {
                await fetch('/api/panic', { method: 'POST' });
                this.panic = true;
            } catch (e) { this.err = String(e); }
        },

        async clearPanic() {
            this.panic = false;
            this.err = '';
            const stalled = this.torrents.filter(t => t.state === 'paused');
            await Promise.all(stalled.map(async (t) => {
                try { await fetch(`/api/torrents/${t.id}/resume`, { method: 'POST' }); }
                catch (e) { /* quiet */ }
            }));
            await this.fetchData();
        },

        vpnClass() {
            return this.vpn.connected ? 'ok' : 'danger';
        },

        vpnText() {
            let s = this.vpn.connected ? 'VPN: ● UP' : 'VPN: ● DOWN';
            if (!this.vpn.connected && this.vpn.reason) {
                const short = String(this.vpn.reason).includes('not carrying traffic') ? 'tunnel dead' : 'iface down';
                s += ' (' + short + ')';
            }
            return (this.vpn.ip_address ? '(' + this.vpn.ip_address + ')  ' : '') + s;
        },

        footerText() {
            if (this.page === 'history') {
                if (this.historyFocus === 'report') {
                    return '↑↓ scroll report  ← back to list  r re-scan  x delete  q close';
                }
                return '↑↓ tabs  j/k navigate  → scan report  ← downloads  enter/o open  r re-scan  s seed/un-seed  x delete  g refresh';
            }
            return 'A - Add | ↑↓ - Tabs | j/k - Navigate | Enter - Files | P - Pause/Resume | T - Settings | X - Delete | Space - Panic';
        },

        cardHtml(t, i) {
            const ic = this.icons();
            let name = t.name || (truncate(String(t.id), 16) + '…');
            let note = '', nc = 'c-unscanned';
            if (t.awaiting_selection) note = ' ' + ic.pick + ' pick';
            else if (t.scan_step) note = ' ' + ic.scan + ' ' + t.scan_step + ' ' + ic.scan;
            else if (t.state === 'complete' && t.scan_result === 'clean') note = ' {~~ Aarrr, the goods be delivered! ~~}';
            let nameHtml = (i === this.selected ? '▶ ' : '  ') + esc(name);
            if (note) nameHtml += ' <span class="' + nc + '">' + esc(note) + '</span>';
            let html = '<span class="c-name">' + nameHtml + '</span>';

            const mal = this.malicious(t);
            const gb = t.size / (1024 * 1024 * 1024);
            const ship = mal ? ic.threat : ic.ship[gb <= 5 ? 0 : gb <= 20 ? 1 : 2];
            const island = mal ? ic.threat : ic.island;
            const globe = mal ? ic.threat : ic.globe;
            const suffix = this.cardSuffixText(t);
            const barW = this.cardBarWidth(this.cardSuffixLen(t));
            let col = Math.round(t.progress / 100 * (barW - 2));
            if (t.progress >= 100) col = barW - 2;
            col = Math.max(0, Math.min(barW - 2, col));
            const sea = '~'.repeat(col) + ship + '~'.repeat(barW - col - 2);
            const st = this.stateLabel(t);
            let tail = globe + '<span class="c-progress">' + esc(sea) + '</span>' + island + suffix;
            html += '<span class="c-tail">' + tail + '</span>';
            if (t.state === 'paused') {
                html += '<span class="c-hint">   Paused - Press P To Resume</span>';
            }
            return html;
        },

        cardSuffixText(t) {
            const st = this.stateLabel(t);
            let s = ' <span class="c-progress">' + t.progress.toFixed(1) + '%</span>' +
                ' <span class="' + st.cls + '">' + esc(st.txt) + '</span>';
            if (t.scan_result) {
                s += ' <span class="c-label">[</span><span class="' + this.scanCls(t.scan_result) + '">' + esc(t.scan_result) + '</span><span class="c-label">]</span>';
            }
            const meta = this.cardMetaCompact(t);
            if (meta) s += ' ' + meta;
            return s;
        },

        cardSuffixLen(t) {
            const st = this.stateLabel(t);
            let s = ' ' + t.progress.toFixed(1) + '% ' + st.txt;
            if (t.scan_result) s += ' [' + t.scan_result + ']';
            const meta = this.cardMetaText(t);
            if (meta) s += ' ' + meta;
            return s.length;
        },

        cardMetaText(t) {
            const ic = this.icons();
            switch (t.state) {
                case 'downloading':
                case 'seeding': {
                    let m = '↓' + this.cRate(t.download_rate) + '  ↑' + this.cRate(t.upload_rate);
                    if (t.peers > 0) m += '  ' + ic.peers + t.peers;
                    return m;
                }
                case 'fetching_metadata':
                    return ic.pend + (t.peers > 0 ? ' ' + t.peers : '') + ' peers...';
                case 'error':
                    return t.error || 'ERROR';
                default:
                    return t.error || '';
            }
        },

        cardBarWidth(suffixChars) {
            const page = this.$root && this.$root.querySelector('.page');
            const w = (page && page.clientWidth) || 800;
            const half = Math.max(30, Math.floor(w / this.charW() / 2));
            const barW = Math.max(10, half - 3 - suffixChars);
            return Math.min(200, barW);
        },

        charW() {
            if (this._charW) return this._charW;
            const probe = document.createElement('span');
            probe.style.cssText = 'font: inherit; visibility: hidden; position: absolute; white-space: nowrap;';
            probe.textContent = 'M'.repeat(100);
            document.body.appendChild(probe);
            this._charW = probe.getBoundingClientRect().width / 100;
            probe.remove();
            return this._charW;
        },

        malicious(t) {
            if (t.scan_result === 'threats_found') return true;
            for (const f of t.files || []) if (f.scan_result === 'threat') return true;
            return false;
        },

        stateLabel(t) {
            switch (t.state) {
                case 'complete': return { txt: 'COMPLETE', cls: 'c-clean' };
                case 'quarantined': return { txt: 'QUARANTINED', cls: 'c-threat' };
                case 'downloading': return { txt: 'DOWNLOADING', cls: 'c-progress' };
                case 'seeding': return { txt: 'SEEDING', cls: 'c-progress' };
                case 'fetching_metadata': return { txt: 'FETCHING METADATA', cls: 'c-label' };
                case 'paused': return { txt: 'PAUSED', cls: 'c-label' };
                case 'scanning': return { txt: 'SCANNING', cls: 'c-unscanned' };
                case 'error': return { txt: 'ERROR', cls: 'c-threat' };
                default: return { txt: String(t.state).toUpperCase(), cls: 'c-label' };
            }
        },

        scanCls(r) {
            switch (r) {
                case 'clean': return 'c-clean';
                case 'unscanned': case 'scanning': return 'c-unscanned';
                default: return 'c-threat';
            }
        },

cardMetaCompact(t) {
            const ic = this.icons();
            switch (t.state) {
                case 'downloading':
                case 'seeding':
                    let m = '<span class="c-label">↓</span><span class="c-progress">' + esc(this.cRate(t.download_rate)) + '</span>' +
                        '<span class="c-label">  ↑</span><span class="c-progress">' + esc(this.cRate(t.upload_rate)) + '</span>';
                    if (t.peers > 0) m += ' <span class="c-label">' + esc(ic.peers + t.peers) + '</span>';
                    return m;
                case 'fetching_metadata':
                    if (t.peers > 0) return '<span class="c-label">' + esc(ic.pend + ' ' + t.peers + ' peers') + '</span>';
                    return '<span class="c-label">' + esc(ic.pend + ' peers...') + '</span>';
                case 'error':
                    return '<span class="c-threat">' + esc(t.error || 'ERROR') + '</span>';
                default:
                    if (t.error) return '<span class="c-threat">' + esc(t.error) + '</span>';
                    return '';
            }
        },

        cRate(b) {
            return fmtRate(b).replace(/ /g, '');
        },

        historyRow(e, i) {
            const ic = this.icons();
            let icon = ic.inbox, cls = 'c-label';
            if (e.root === 'clean') { icon = ic.clean; cls = 'c-clean'; }
            else if (e.root === 'quarantine') { icon = ic.threat; cls = 'c-threat'; }
            else if (e.root === 'scanning') { icon = ic.unscanned; cls = 'c-unscanned'; }
            let name = e.name || '';
            name = truncate(name, 40);
            const root = ('[' + e.root + ']').padEnd(13, ' ');
            const size = padLeft(fmtBytes(e.size), 11);
            let line = (i === this.historySel ? '▶ ' : '  ');
            line += '<span class="' + cls + '">' + esc(icon) + ' ' + esc(name) + '  ' + esc(root) + ' ' + esc(size) + '  </span>';
            line += '<span class="c-label">' + esc(fmtTime(e.mod_time)) + '</span>';
            if (this.rescanning && e.infohash === this.rescanning) {
                line += ' <span class="c-unscanned">' + esc(ic.scan + ' scanning ' + ic.scan) + '</span>';
            }
            if (e.seeding) {
                line += ' <span class="c-clean">⬆ seeding</span>';
            }
            return line;
        },
    };
}