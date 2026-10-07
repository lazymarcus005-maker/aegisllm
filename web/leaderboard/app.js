(() => {
  const pollMs = 2000;
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const els = {
    total: document.getElementById("total-counter"),
    card: document.getElementById("total-card"),
    updated: document.getElementById("updated-at"),
    list: document.getElementById("leaderboard"),
    empty: document.getElementById("empty-state"),
    blocked: document.getElementById("blocked"),
    tokenized: document.getElementById("tokenized"),
    redacted: document.getElementById("redacted"),
    review: document.getElementById("review"),
    allowed: document.getElementById("allowed")
  };
  let currentTotal = 0;
  let lastUpdated = "";

  const format = value => new Intl.NumberFormat().format(value || 0);
  const animateNumber = (node, from, to, duration = 700) => {
    if (reducedMotion || from === to) { node.textContent = format(to); return; }
    const start = performance.now();
    const tick = now => {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      node.textContent = format(Math.round(from + (to - from) * eased));
      if (progress < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  };

  const renderRows = rows => {
    els.list.replaceChildren();
    if (!rows || rows.length === 0) { els.empty.hidden = false; return; }
    els.empty.hidden = true;
    const max = Math.max(...rows.map(row => row.count), 1);
    rows.forEach((row, index) => {
      const item = document.createElement("div");
      item.className = "leader-row";
      const rank = document.createElement("div");
      rank.className = "rank";
      rank.textContent = ["🥇", "🥈", "🥉"][index] || `#${index + 1}`;
      const category = document.createElement("div");
      category.className = "category";
      const title = document.createElement("strong");
      title.textContent = row.category || "Unknown";
      const subtype = document.createElement("span");
      subtype.textContent = row.subtype || "unspecified";
      category.append(title, subtype);
      const track = document.createElement("div");
      track.className = "bar-track";
      const fill = document.createElement("div");
      fill.className = "bar-fill";
      fill.style.width = `${Math.max((row.count / max) * 100, 1)}%`;
      track.append(fill);
      const count = document.createElement("div");
      count.className = "count";
      count.textContent = format(row.count);
      item.append(rank, category, track, count);
      els.list.append(item);
    });
  };

  const update = async () => {
    try {
      const response = await fetch("/api/protection-stats", { cache: "no-store" });
      if (!response.ok) throw new Error("stats request failed");
      const stats = await response.json();
      const nextTotal = Number(stats.total_prevented || 0);
      animateNumber(els.total, currentTotal, nextTotal);
      if (nextTotal > currentTotal && !reducedMotion) {
        els.card.classList.remove("pulse");
        void els.card.offsetWidth;
        els.card.classList.add("pulse");
        burst();
      }
      currentTotal = nextTotal;
      ["blocked", "tokenized", "redacted", "review", "allowed"].forEach(key => { els[key].textContent = format(stats[key]); });
      renderRows(stats.by_category);
      const updated = stats.updated_at ? new Date(stats.updated_at).toLocaleTimeString() : "";
      if (updated && updated !== lastUpdated) { els.updated.textContent = `Updated / อัปเดต ${updated}`; lastUpdated = updated; }
    } catch (_) {
      els.updated.textContent = "Waiting for gateway / รอ gateway…";
    }
  };

  const canvas = document.getElementById("ambient-canvas");
  const ctx = canvas.getContext("2d");
  const particles = Array.from({ length: 24 }, () => ({ x: Math.random(), y: Math.random(), r: 1 + Math.random() * 2, v: .00015 + Math.random() * .00025, phase: Math.random() * 6 }));
  const confetti = [];
  const resize = () => { canvas.width = window.innerWidth * devicePixelRatio; canvas.height = window.innerHeight * devicePixelRatio; ctx.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0); };
  const drawShield = (x, y, size) => { ctx.beginPath(); ctx.moveTo(x, y - size); ctx.lineTo(x + size * .72, y - size * .55); ctx.lineTo(x + size * .58, y + size * .42); ctx.lineTo(x, y + size); ctx.lineTo(x - size * .58, y + size * .42); ctx.lineTo(x - size * .72, y - size * .55); ctx.closePath(); ctx.fill(); };
  const floatParticles = time => {
    ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
    ctx.fillStyle = "rgba(120, 127, 230, .24)";
    particles.forEach(p => { p.y -= p.v; if (p.y < -.05) p.y = 1.05; drawShield(p.x * window.innerWidth, p.y * window.innerHeight + Math.sin(time / 1200 + p.phase) * 7, p.r * 2.2); });
    confetti.forEach((piece, index) => { piece.y += piece.v; piece.x += piece.dx; piece.rotation += piece.spin; ctx.save(); ctx.translate(piece.x, piece.y); ctx.rotate(piece.rotation); ctx.fillStyle = piece.color; ctx.fillRect(-2, -2, 4, 4); ctx.restore(); if (piece.y > window.innerHeight + 10) confetti.splice(index, 1); });
    requestAnimationFrame(floatParticles);
  };
  const burst = () => { for (let i = 0; i < 26; i += 1) confetti.push({ x: window.innerWidth * .5 + (Math.random() - .5) * 180, y: 110 + Math.random() * 35, v: 1.2 + Math.random() * 2.1, dx: (Math.random() - .5) * 1.6, rotation: Math.random() * 6, spin: (Math.random() - .5) * .18, color: ["#5d63f5", "#a36df4", "#1ca67a"][i % 3] }); };
  if (!reducedMotion) { resize(); window.addEventListener("resize", resize); requestAnimationFrame(floatParticles); }
  update();
  window.setInterval(update, pollMs);
})();
