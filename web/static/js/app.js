/* ============================================================================
   CVE.ICU shared runtime.

   Every page loads this one file instead of re-emitting the same fetch, format
   and chart helpers inline. No third-party dependencies: the charts here are
   counts, and counts draw fine with SVG and flexbox.
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
        const res = await fetch(url, { signal: ctrl.signal });
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

  const el = s => document.querySelector(s);
  const all = s => [...document.querySelectorAll(s)];
  const esc = s => String(s ?? '').replace(/[&<>"]/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  /* --------------------------------------------------------------- charts */
  const chart = {
    /** Sparkline / trend line as inline SVG. */
    spark(values, w = 120, h = 40, opt = {}) {
      const v = values.filter(x => Number.isFinite(x));
      if (v.length < 2) return '';
      const max = Math.max(...v), min = Math.min(...v), span = max - min || 1;
      const pts = v.map((x, i) => [
        (i / (v.length - 1)) * w,
        h - ((x - min) / span) * (h - 2) - 1
      ]);
      const line = pts.map(p => p[0].toFixed(1) + ',' + p[1].toFixed(1)).join(' ');
      return `<svg class="spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true">
        <polygon points="0,${h} ${line} ${w},${h}" fill="currentColor" opacity=".16"/>
        <polyline points="${line}" fill="none" stroke="currentColor" stroke-width="1.6"
          stroke-linejoin="round" stroke-linecap="round" vector-effect="non-scaling-stroke"/>
      </svg>`;
    },

    /** Vertical bars. items: [{label, value, current?, alt?}] */
    bars(node, items, opt = {}) {
      const target = typeof node === 'string' ? el(node) : node;
      if (!target) return;
      if (!items.length) { target.innerHTML = '<div class="empty">No data</div>'; return; }
      const max = Math.max(...items.map(i => i.value)) || 1;
      target.innerHTML =
        `<div class="bars ${opt.tall ? 'tall' : ''}">` +
        items.map(i => `<div class="b ${i.current ? 'cur' : ''} ${i.alt ? 'alt' : ''}"
            style="height:${(i.value / max * 100).toFixed(1)}%"
            data-t="${esc(i.label)}: ${fmt.n(i.value)}"></div>`).join('') +
        '</div>' +
        (opt.axis === false ? '' :
          `<div class="ax">${(opt.ticks || [items[0], items[items.length - 1]])
            .map(t => `<span>${esc(t.label ?? t)}</span>`).join('')}</div>`);
    },

    /** Horizontal bars. items: [{label, value, sub?}] */
    hbars(node, items, opt = {}) {
      const target = typeof node === 'string' ? el(node) : node;
      if (!target) return;
      if (!items.length) { target.innerHTML = '<div class="empty">No data</div>'; return; }
      const max = Math.max(...items.map(i => i.value)) || 1;
      target.innerHTML = '<div class="hbars">' + items.map(i => `
        <div class="hb">
          <span class="k" title="${esc(i.label)}">${esc(i.label)}</span>
          <span class="t"><i style="width:${(i.value / max * 100).toFixed(1)}%"></i></span>
          <span class="v">${opt.compact ? fmt.compact(i.value) : fmt.n(i.value)}</span>
        </div>`).join('') + '</div>';
    },

    /** Ranked list with inline magnitude bars. */
    rank(node, items, opt = {}) {
      const target = typeof node === 'string' ? el(node) : node;
      if (!target) return;
      if (!items.length) { target.innerHTML = '<div class="empty">No data</div>'; return; }
      const max = Math.max(...items.map(i => i.value)) || 1;
      target.innerHTML = items.map((i, n) => `
        <div class="r">
          <span class="i">${n + 1}</span>
          <span class="t">
            <em>${esc(i.label)}${i.sub ? `<small>${esc(i.sub)}</small>` : ''}</em>
            <span class="g ${opt.tone || ''}"><i style="width:${(i.value / max * 100).toFixed(1)}%"></i></span>
          </span>
          <span class="v">${opt.compact ? fmt.compact(i.value) : fmt.n(i.value)}${
            i.note ? `<small>${esc(i.note)}</small>` : ''}</span>
        </div>`).join('');
    },

    /** Calendar heatmap. days: [{date:'YYYY-MM-DD', value}] */
    heat(node, days, opt = {}) {
      const target = typeof node === 'string' ? el(node) : node;
      if (!target) return;
      if (!days.length) { target.innerHTML = '<div class="empty">No data</div>'; return; }
      const vals = days.map(d => d.value).filter(v => v > 0).sort((a, b) => a - b);
      const q = p => vals[Math.floor(vals.length * p)] || 0;
      const cuts = [q(.25), q(.5), q(.75), q(.92)];
      const level = v => !v ? 0 : v <= cuts[0] ? 1 : v <= cuts[1] ? 2 : v <= cuts[2] ? 3 : 4;

      // pad so the first column starts on a Sunday
      const first = new Date(days[0].date + 'T00:00:00');
      const pad = first.getDay();
      const cells = Array(pad).fill(null).concat(days);

      target.innerHTML =
        `<div class="heat">${cells.map(d => d
          ? `<i data-l="${level(d.value)}" title="${d.date}: ${fmt.n(d.value)} CVEs"></i>`
          : '<i style="background:transparent"></i>').join('')}</div>` +
        `<div class="heat-legend"><span>Fewer</span>
          ${[0, 1, 2, 3, 4].map(l => `<i data-l="${l}"></i>`).join('')}
          <span>More</span>
          <span style="margin-left:auto">${fmt.n(days.reduce((s, d) => s + d.value, 0))} CVEs
          across ${days.length} days</span></div>`;
    }
  };

  /* ---------------------------------------------------------------- table */
  /** cols: [{key, label, num?, fmt?, bar?, raw?}] */
  function table(node, rows, cols, opt = {}) {
    const target = typeof node === 'string' ? el(node) : node;
    if (!target) return;
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
      target.innerHTML = `<div class="tw"><table>
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

      target.querySelectorAll('th[data-k]').forEach(th => {
        th.onclick = () => {
          const k = th.dataset.k;
          sort = sort.key === k ? { key: k, dir: -sort.dir } : { key: k, dir: -1 };
          draw();
        };
      });
    }
    draw();
  }

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

  /** Stamp freshness into the bar and footer from any summary payload. */
  function freshness(meta) {
    all('[data-fresh]').forEach(e => { e.textContent = fmt.ago(meta.data_as_of); });
    all('[data-asof]').forEach(e => { e.textContent = fmt.date(meta.data_as_of); });
    all('[data-srcrun]').forEach(e => { e.textContent = fmt.ago(meta.source_last_run); });
  }

  /** Render an error into a container rather than leaving a skeleton forever. */
  function fail(node, err) {
    const target = typeof node === 'string' ? el(node) : node;
    if (target) target.innerHTML =
      `<div class="empty">Could not load this data.<br>
       <span class="faint" style="font-size:12px">${esc(err.message || err)}</span></div>`;
    console.error(err);
  }

  /** Standard page bootstrap: load summary, stamp freshness, run the page. */
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

  window.CVE = { json, fmt, chart, table, el, all, esc, theme, freshness, fail, page };
})();
