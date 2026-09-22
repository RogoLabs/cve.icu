/* ============================================================================
   CVE.ICU shared runtime.

   One file for every page: fetching, formatting, charts and export. Charts are
   inline SVG rather than a charting library - counts draw fine with SVG, it
   keeps the site free of third-party JavaScript, and it means every chart can
   be exported as a PNG without a rasteriser.
   ========================================================================== */
(function () {
  'use strict';

  /* ------------------------------------------------------------- fetching */
  const cache = new Map();

  async function json(name, { retries = 2, timeoutMs = 12000 } = {}) {
    const url = 'data/' + name;
    if (cache.has(url)) return cache.get(url);

    const attempt = async (n) => {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        // Always revalidate: the build runs hourly, and a cached payload would
        // quietly serve yesterday's counts. Unchanged files come back 304.
        const res = await fetch(url, { signal: ctrl.signal, cache: 'no-cache' });
        if (!res.ok) throw Object.assign(new Error(`HTTP ${res.status} for ${url}`), { status: res.status });
        return await res.json();
      } catch (err) {
        const retryable = err.name === 'AbortError' ||
          [408, 425, 429, 500, 502, 503, 504].includes(err.status) ||
          /failed to fetch|networkerror/i.test(err.message || '');
        if (n < retries && retryable) {
          await new Promise(r => setTimeout(r, 300 * 2 ** n));
          return attempt(n + 1);
        }
        throw err;
      } finally {
        clearTimeout(timer);
      }
    };

    const p = attempt(0).catch(err => { cache.delete(url); throw err; });
    cache.set(url, p);
    return p;
  }

  /* ----------------------------------------------------------- formatting */
  const fmt = {
    n: v => (v == null || Number.isNaN(+v) ? '—' : (+v).toLocaleString('en-US')),
    compact: v => {
      if (v == null || Number.isNaN(+v)) return '—';
      v = +v;
      if (Math.abs(v) >= 1e6) return (v / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
      if (Math.abs(v) >= 1e3) return (v / 1e3).toFixed(1).replace(/\.0$/, '') + 'k';
      return String(v);
    },
    pct: (v, d = 1) => (v == null ? '—' : (v > 0 ? '+' : '') + (+v).toFixed(d) + '%'),
    share: (a, b, d = 1) => (!b ? '—' : (a / b * 100).toFixed(d) + '%'),
    ago: iso => {
      if (!iso) return '—';
      const h = (Date.now() - new Date(iso).getTime()) / 36e5;
      if (h < 0) return 'just now';
      if (h < 1) return Math.max(1, Math.round(h * 60)) + ' min ago';
      if (h < 48) return Math.round(h) + ' h ago';
      return Math.round(h / 24) + ' d ago';
    },
    date: iso => iso ? new Date(iso).toLocaleDateString('en-US',
      { year: 'numeric', month: 'short', day: 'numeric' }) : '—',
    day: iso => iso ? new Date(iso + 'T00:00:00').toLocaleDateString('en-US',
      { month: 'short', day: 'numeric' }) : '—'
  };

  const el = s => (typeof s === 'string' ? document.querySelector(s) : s);
  const all = s => [...document.querySelectorAll(s)];
  const esc = s => String(s ?? '').replace(/[&<>"]/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  /* --------------------------------------------------------------- export */
  function download(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  const slug = s => String(s || 'cve-icu').toLowerCase()
    .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60);

  function toCSV(rows) {
    if (!rows || !rows.length) return '';
    const cols = Object.keys(rows[0]);
    const cell = v => {
      const s = v == null ? '' : String(v);
      return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    return [cols.join(','), ...rows.map(r => cols.map(c => cell(r[c])).join(','))].join('\n');
  }

  const exportData = {
    csv(rows, name) { download(new Blob([toCSV(rows)], { type: 'text/csv;charset=utf-8' }), slug(name) + '.csv'); },
    json(rows, name) { download(new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' }), slug(name) + '.json'); },

    /** Rasterise an inline SVG chart to PNG.
     *  CSS custom properties do not survive serialisation, so every paint and
     *  font is resolved to a literal value on a clone before encoding. */
    async png(svg, name, scale = 2) {
      const clone = svg.cloneNode(true);
      const srcNodes = svg.querySelectorAll('*');
      const dstNodes = clone.querySelectorAll('*');
      const PROPS = ['fill', 'stroke', 'stroke-width', 'stroke-dasharray', 'opacity',
                     'font-family', 'font-size', 'font-weight', 'text-anchor'];
      srcNodes.forEach((src, i) => {
        const cs = getComputedStyle(src);
        const dst = dstNodes[i];
        PROPS.forEach(p => {
          const v = cs.getPropertyValue(p);
          if (v && v !== 'none' || (p === 'fill' && v === 'none')) dst.setAttribute(p, v.trim());
        });
        dst.removeAttribute('class');
      });

      // Size from the viewBox, not the rendered box, so an export is the same
      // resolution whether it was taken on a phone or a wide monitor.
      const vb = (svg.getAttribute('viewBox') || '').split(/[\s,]+/).map(Number);
      const box = svg.getBoundingClientRect();
      const w = Math.round(vb[2] || box.width || 900);
      const h = Math.round(vb[3] || box.height || 320);
      clone.setAttribute('width', w);
      clone.setAttribute('height', h);
      clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');

      // opaque background so the PNG is readable outside the page's theme
      const bg = getComputedStyle(document.body).backgroundColor || '#fff';
      const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      rect.setAttribute('x', vb[0] ?? 0); rect.setAttribute('y', vb[1] ?? 0);
      rect.setAttribute('width', vb[2] || w); rect.setAttribute('height', vb[3] || h);
      rect.setAttribute('fill', bg);
      clone.insertBefore(rect, clone.firstChild);

      const src = new XMLSerializer().serializeToString(clone);
      const url = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(src);

      await new Promise((resolve, reject) => {
        const img = new Image();
        img.onload = () => {
          const c = document.createElement('canvas');
          c.width = w * scale; c.height = h * scale;
          const ctx = c.getContext('2d');
          ctx.drawImage(img, 0, 0, c.width, c.height);
          c.toBlob(b => { download(b, slug(name) + '.png'); resolve(); }, 'image/png');
        };
        img.onerror = reject;
        img.src = url;
      });
    }
  };

  /** Attach PNG / CSV / JSON buttons under a chart or table. */
  function attachExports(host, { svg, rows, name }) {
    if (!host) return;
    const bar = document.createElement('div');
    bar.className = 'exp';
    const mk = (label, fn) => {
      const b = document.createElement('button');
      b.type = 'button'; b.className = 'exp-btn'; b.textContent = label;
      b.addEventListener('click', async () => {
        const was = b.textContent;
        b.disabled = true; b.textContent = '…';
        try { await fn(); b.textContent = '✓'; }
        catch (e) { console.error(e); b.textContent = 'failed'; }
        setTimeout(() => { b.textContent = was; b.disabled = false; }, 900);
      });
      return b;
    };
    if (svg) bar.appendChild(mk('PNG', () => exportData.png(svg, name)));
    if (rows && rows.length) {
      bar.appendChild(mk('CSV', () => exportData.csv(rows, name)));
      bar.appendChild(mk('JSON', () => exportData.json(rows, name)));
    }
    if (bar.children.length) host.appendChild(bar);
  }

  /* -------------------------------------------------------------- tooltip */
  let tip;
  function showTip(text, x, y) {
    if (!tip) {
      tip = document.createElement('div');
      tip.className = 'tip';
      document.body.appendChild(tip);
    }
    tip.textContent = text;
    tip.style.display = 'block';
    const r = tip.getBoundingClientRect();
    tip.style.left = Math.min(window.innerWidth - r.width - 8, Math.max(8, x - r.width / 2)) + 'px';
    tip.style.top = (y - r.height - 10) + 'px';
  }
  const hideTip = () => { if (tip) tip.style.display = 'none'; };

  function wireTips(svg) {
    svg.addEventListener('mousemove', e => {
      const t = e.target.closest('[data-tip]');
      if (t) showTip(t.dataset.tip, e.clientX, e.clientY);
      else hideTip();
    });
    svg.addEventListener('mouseleave', hideTip);
  }

  /* --------------------------------------------------------------- charts */
  const NS = 'http://www.w3.org/2000/svg';

  function svgEl(host, w, h, label) {
    const s = document.createElementNS(NS, 'svg');
    s.setAttribute('viewBox', `0 0 ${w} ${h}`);
    s.setAttribute('role', 'img');
    s.setAttribute('preserveAspectRatio', 'xMidYMid meet');
    if (label) s.setAttribute('aria-label', label);
    s.classList.add('chart-svg');
    host.appendChild(s);
    return s;
  }

  function niceTicks(max, count = 4) {
    if (max <= 0) return [0];
    const raw = max / count;
    const mag = 10 ** Math.floor(Math.log10(raw));
    const step = [1, 2, 2.5, 5, 10].map(m => m * mag).find(s => s >= raw) || mag * 10;
    const out = [];
    // Run past max, not up to it: the top tick is the scale's ceiling, so if it
    // stops below max the tallest bar is drawn above the plot area.
    for (let v = 0; v < max; v += step) out.push(v);
    out.push(out[out.length - 1] + step);
    return out;
  }

  const chart = {
    spark(values, w = 120, h = 40) {
      const v = values.filter(x => Number.isFinite(x));
      if (v.length < 2) return '';
      const max = Math.max(...v), min = Math.min(...v), span = max - min || 1;
      const pts = v.map((x, i) => [(i / (v.length - 1)) * w, h - ((x - min) / span) * (h - 2) - 1]);
      const line = pts.map(p => p[0].toFixed(1) + ',' + p[1].toFixed(1)).join(' ');
      return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">
        <polygon points="0,${h} ${line} ${w},${h}" fill="currentColor" opacity=".16"/>
        <polyline points="${line}" fill="none" stroke="currentColor" stroke-width="1.6"
          stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>
      </svg>`;
    },

    /** Vertical bars. items: [{label, value, current?, alt?}] */
    bars(node, items, opt = {}) {
      const host = el(node);
      if (!host) return;
      host.innerHTML = '';
      if (!items.length) { host.innerHTML = '<div class="empty">No data</div>'; return; }

      const W = 1000, H = opt.tall ? 300 : 210;
      const mL = 46, mR = 10, mT = 12, mB = 26;
      const iw = W - mL - mR, ih = H - mT - mB;
      const max = Math.max(...items.map(i => i.value)) || 1;
      const ticks = niceTicks(max);
      const top = ticks[ticks.length - 1] || max;
      const bw = Math.max(1, (iw / items.length) * 0.78);
      const y = v => mT + ih - (v / top) * ih;

      const svg = svgEl(host, W, H, opt.label || 'Bar chart');
      const parts = [];
      ticks.forEach(t => {
        parts.push(`<line class="gl" x1="${mL}" y1="${y(t).toFixed(1)}" x2="${mL + iw}" y2="${y(t).toFixed(1)}"/>`);
        parts.push(`<text class="ax" x="${mL - 8}" y="${(y(t) + 4).toFixed(1)}" text-anchor="end">${fmt.compact(t)}</text>`);
      });
      items.forEach((d, i) => {
        const cx = mL + (i + 0.5) * (iw / items.length);
        const hgt = Math.max(1, (d.value / top) * ih);
        const cls = 'cbar' + (d.current ? ' cur' : '') + (d.alt ? ' alt' : '');
        parts.push(`<rect class="${cls}" x="${(cx - bw / 2).toFixed(1)}" y="${(mT + ih - hgt).toFixed(1)}"
          width="${bw.toFixed(1)}" height="${hgt.toFixed(1)}" rx="1.5"
          data-tip="${esc(d.label)}: ${fmt.n(d.value)}" data-key="${esc(d.label)}"/>`);
      });
      (opt.ticks || [items[0].label, items[items.length - 1].label]).forEach((t, i, arr) => {
        const x = mL + (arr.length === 1 ? iw / 2 : (i / (arr.length - 1)) * iw);
        parts.push(`<text class="ax" x="${x.toFixed(1)}" y="${H - 8}" text-anchor="${
          i === 0 ? 'start' : i === arr.length - 1 ? 'end' : 'middle'}">${esc(t)}</text>`);
      });
      svg.innerHTML = parts.join('');
      wireTips(svg);
      if (opt.onSelect) {
        svg.classList.add('clickable');
        svg.addEventListener('click', e => {
          const r = e.target.closest('[data-key]');
          if (r) opt.onSelect(r.dataset.key);
        });
      }
      if (opt.export !== false) {
        attachExports(host, {
          svg, name: opt.name || opt.label || 'chart',
          rows: items.map(i => ({ label: i.label, value: i.value }))
        });
      }
      return svg;
    },

    /** Horizontal bars. items: [{label, value}] */
    hbars(node, items, opt = {}) {
      const host = el(node);
      if (!host) return;
      host.innerHTML = '';
      if (!items.length) { host.innerHTML = '<div class="empty">No data</div>'; return; }

      const rowH = 22, W = 1000, mL = 190, mR = 92, mT = 6;
      const H = mT * 2 + items.length * rowH;
      const iw = W - mL - mR;
      const max = Math.max(...items.map(i => i.value)) || 1;

      const svg = svgEl(host, W, H, opt.label || 'Horizontal bar chart');
      const parts = [];
      items.forEach((d, i) => {
        const y = mT + i * rowH;
        const w = Math.max(1, (d.value / max) * iw);
        parts.push(`<text class="ax hb-k" x="${mL - 10}" y="${y + rowH / 2 + 4}" text-anchor="end">${esc(d.label)}</text>`);
        parts.push(`<rect class="track" x="${mL}" y="${y + 4}" width="${iw}" height="${rowH - 9}" rx="2.5"/>`);
        parts.push(`<rect class="cbar" x="${mL}" y="${y + 4}" width="${w.toFixed(1)}" height="${rowH - 9}" rx="2.5"
          data-tip="${esc(d.label)}: ${fmt.n(d.value)}"/>`);
        parts.push(`<text class="ax hb-v" x="${mL + iw + 10}" y="${y + rowH / 2 + 4}">${
          opt.compact ? fmt.compact(d.value) : fmt.n(d.value)}</text>`);
      });
      svg.innerHTML = parts.join('');
      wireTips(svg);
      if (opt.export !== false) {
        attachExports(host, {
          svg, name: opt.name || opt.label || 'chart',
          rows: items.map(i => ({ label: i.label, value: i.value }))
        });
      }
      return svg;
    },

    /** Calendar heatmap. days: [{date:'YYYY-MM-DD', value}] */
    heat(node, days, opt = {}) {
      const host = el(node);
      if (!host) return;
      host.innerHTML = '';
      if (!days.length) { host.innerHTML = '<div class="empty">No data</div>'; return; }

      const vals = days.map(d => d.value).filter(v => v > 0).sort((a, b) => a - b);
      const q = p => vals[Math.floor(vals.length * p)] || 0;
      const cuts = [q(.25), q(.5), q(.75), q(.92)];
      const level = v => !v ? 0 : v <= cuts[0] ? 1 : v <= cuts[1] ? 2 : v <= cuts[2] ? 3 : 4;

      const cell = 13, gap = 3, pad = 26;
      const first = new Date(days[0].date + 'T00:00:00');
      const offset = first.getDay();
      const weeks = Math.ceil((days.length + offset) / 7);
      const W = pad + weeks * (cell + gap), H = pad + 7 * (cell + gap) + 4;

      const svg = svgEl(host, W, H, 'Calendar heatmap of daily CVE counts');
      const parts = [];
      ['', 'Mon', '', 'Wed', '', 'Fri', ''].forEach((lbl, i) => {
        if (lbl) parts.push(`<text class="ax" x="${pad - 6}" y="${pad + i * (cell + gap) + cell - 2}" text-anchor="end">${lbl}</text>`);
      });
      let lastMonth = '';
      days.forEach((d, i) => {
        const idx = i + offset;
        const col = Math.floor(idx / 7), row = idx % 7;
        const x = pad + col * (cell + gap), y = pad + row * (cell + gap);
        parts.push(`<rect class="hc" data-l="${level(d.value)}" x="${x}" y="${y}"
          width="${cell}" height="${cell}" rx="2.5"
          data-tip="${d.date}: ${fmt.n(d.value)} CVEs"/>`);
        const m = d.date.slice(0, 7);
        if (m !== lastMonth && row <= 1) {
          lastMonth = m;
          const name = new Date(d.date + 'T00:00:00').toLocaleDateString('en-US', { month: 'short' });
          parts.push(`<text class="ax" x="${x}" y="${pad - 8}">${name}</text>`);
        }
      });
      svg.innerHTML = parts.join('');
      wireTips(svg);

      const legend = document.createElement('div');
      legend.className = 'heat-legend';
      legend.innerHTML = `<span>Fewer</span>${[0, 1, 2, 3, 4]
        .map(l => `<i data-l="${l}"></i>`).join('')}<span>More</span>
        <span style="margin-left:auto">${fmt.n(days.reduce((s, d) => s + d.value, 0))} CVEs across ${days.length} days</span>`;
      host.appendChild(legend);

      if (opt.export !== false) {
        attachExports(host, {
          svg, name: opt.name || 'cve-icu-daily-counts',
          rows: days.map(d => ({ date: d.date, cves: d.value }))
        });
      }
      return svg;
    },

    /** Ranked list with inline magnitude bars (a list, not a chart - CSV only). */
    rank(node, items, opt = {}) {
      const host = el(node);
      if (!host) return;
      if (!items.length) { host.innerHTML = '<div class="empty">No data</div>'; return; }
      const max = Math.max(...items.map(i => i.value)) || 1;
      host.innerHTML = items.map((i, n) => `
        <div class="r">
          <span class="i">${n + 1}</span>
          <span class="t">
            <em>${esc(i.label)}${i.sub ? `<small>${esc(i.sub)}</small>` : ''}</em>
            <span class="g ${opt.tone || ''}"><i style="width:${(i.value / max * 100).toFixed(1)}%"></i></span>
          </span>
          <span class="v">${opt.compact ? fmt.compact(i.value) : fmt.n(i.value)}${
            i.note ? `<small>${esc(i.note)}</small>` : ''}</span>
        </div>`).join('');
      if (opt.export !== false && opt.name) {
        attachExports(host, { rows: items.map(i => ({ label: i.label, value: i.value })), name: opt.name });
      }
    }
  };

  /* ---------------------------------------------------------------- table */
  function table(node, rows, cols, opt = {}) {
    const host = el(node);
    if (!host) return;
    let sort = opt.sort || { key: cols.find(c => c.num)?.key, dir: -1 };

    const maxes = {};
    cols.filter(c => c.bar).forEach(c => {
      maxes[c.key] = Math.max(...rows.map(r => +r[c.key] || 0)) || 1;
    });

    function draw() {
      const data = [...rows].sort((a, b) => {
        const x = a[sort.key], y = b[sort.key];
        if (typeof x === 'number' && typeof y === 'number') return (x - y) * sort.dir;
        return String(x).localeCompare(String(y)) * sort.dir;
      });
      host.innerHTML = `<div class="tw"><table>
        <thead><tr>${cols.map(c => `<th class="${c.num ? 'num' : ''} sortable" data-k="${c.key}">
          ${esc(c.label)}${sort.key === c.key ? `<span class="ar">${sort.dir < 0 ? '▼' : '▲'}</span>` : ''}
        </th>`).join('')}</tr></thead>
        <tbody>${data.map(r => `<tr>${cols.map(c => {
          let v = r[c.key];
          let disp = c.fmt ? c.fmt(v, r)
            : typeof v === 'number' ? (c.raw ? String(v) : fmt.n(v))
            : esc(v ?? '—');
          if (c.bar) disp += `<span class="g" style="display:inline-block;width:54px;margin-left:9px;vertical-align:middle"><i style="width:${((+v || 0) / maxes[c.key] * 100).toFixed(1)}%"></i></span>`;
          return `<td class="${c.num ? 'num' : ''}">${disp}</td>`;
        }).join('')}</tr>`).join('')}</tbody></table></div>`;

      host.querySelectorAll('th[data-k]').forEach(th => {
        th.onclick = () => {
          const k = th.dataset.k;
          sort = sort.key === k ? { key: k, dir: -sort.dir } : { key: k, dir: -1 };
          draw();
        };
      });
      if (opt.export !== false && opt.name) {
        attachExports(host, {
          rows: data.map(r => Object.fromEntries(cols.map(c => [c.label, r[c.key]]))),
          name: opt.name
        });
      }
    }
    draw();
  }

  /* ------------------------------------------------------------- URL state */
  const url = {
    get(key, fallback = null) {
      const v = new URLSearchParams(location.search).get(key);
      return v === null ? fallback : v;
    },
    set(obj, { replace = true } = {}) {
      const p = new URLSearchParams(location.search);
      Object.entries(obj).forEach(([k, v]) => {
        if (v == null || v === '') p.delete(k); else p.set(k, v);
      });
      const q = p.toString();
      const next = location.pathname + (q ? '?' + q : '');
      history[replace ? 'replaceState' : 'pushState'](null, '', next);
    },
    /** Copy the current URL, reporting on the button that asked. */
    async share(btn) {
      try {
        await navigator.clipboard.writeText(location.href);
        if (btn) { const was = btn.textContent; btn.textContent = 'Copied'; setTimeout(() => btn.textContent = was, 1200); }
      } catch (_) {
        if (btn) btn.textContent = location.href;
      }
    }
  };

  /* ---------------------------------------------------------------- chrome */
  function theme() {
    const root = document.documentElement;
    const btn = el('#theme');
    if (!btn) return;
    btn.onclick = () => {
      const light = root.dataset.theme !== 'light';
      root.dataset.theme = light ? 'light' : 'dark';
      try { localStorage.setItem('cveicu-theme', light ? 'light' : 'dark'); } catch (_) {}
    };
  }

  /* Two different ages, and conflating them overstated our freshness.
     source_last_run is when the producer last gathered the data; data_as_of is
     only when we downloaded it. The producer runs on its own schedule, so a
     download minutes old routinely carries a snapshot hours old. Anything
     labelled as data freshness reads source_last_run, and data_as_of is shown
     only where we mean our own build. Fall back when there is no manifest. */
  function freshness(meta) {
    const dataAge = meta.source_last_run || meta.data_as_of;
    all('[data-fresh]').forEach(e => { e.textContent = fmt.ago(dataAge); });
    all('[data-asof]').forEach(e => { e.textContent = fmt.date(dataAge); });
    all('[data-srcrun]').forEach(e => { e.textContent = fmt.ago(meta.source_last_run); });
    all('[data-built]').forEach(e => { e.textContent = fmt.ago(meta.data_as_of); });
  }

  function fail(node, err) {
    const host = el(node);
    if (host) host.innerHTML =
      `<div class="empty">Could not load this data.<br>
       <span class="faint" style="font-size:12px">${esc(err.message || err)}</span></div>`;
    console.error(err);
  }

  async function page(fn) {
    theme();
    try {
      const summary = await json('homepage_summary.json');
      freshness(summary);
      await fn(summary);
    } catch (err) {
      fail('#main', err);
    }
  }

  window.CVE = { json, fmt, chart, table, el, all, esc, theme, freshness, fail, page,
                 exportData, attachExports, download, toCSV, url };
})();
