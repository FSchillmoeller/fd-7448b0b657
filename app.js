"use strict";
/* Finanz-Dashboard – entschlüsselt die Daten nur im Browser.
   Schlüsselkette: Passkey (Face ID) --PRF--> KEK --entpackt--> Datenschlüssel --entschlüsselt--> data.enc */

const enc = new TextEncoder();
const $ = (s, el = document) => el.querySelector(s);
const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const b64e = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const b64ud = s => b64d(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
const b64ue = b => b64e(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const zufall = n => crypto.getRandomValues(new Uint8Array(n));

// ------------------------------------------------------------------ Krypto
async function kekAusPrf(prf) {
  const basis = await crypto.subtle.importKey("raw", prf, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: enc.encode("finanz-dashboard"), info: enc.encode("kek v1") },
    basis, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function kekAusPasswort(pw, salt, iter) {
  const basis = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter },
    basis, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function verpacken(kek, roh) {
  const iv = zufall(12);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode("zugang v1") }, kek, roh);
  return { iv: b64e(iv), ct: b64e(ct) };
}
async function entpacken(kek, w) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(w.iv), additionalData: enc.encode("zugang v1") }, kek, b64d(w.ct)));
}
async function datenEntschluesseln(dk, paket) {
  const key = await crypto.subtle.importKey("raw", dk, "AES-GCM", false, ["decrypt"]);
  const gz = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(paket.iv), additionalData: enc.encode("finanz-dashboard v1") }, key, b64d(paket.ct));
  const text = await new Response(new Blob([gz]).stream().pipeThrough(new DecompressionStream("gzip"))).text();
  return JSON.parse(text);
}

// ------------------------------------------------------------------ Passkey
const rpId = location.hostname;
async function passkeyPrf(zugang) {
  const cred = await navigator.credentials.get({ publicKey: {
    challenge: zufall(32), rpId, userVerification: "required", timeout: 60000,
    allowCredentials: (zugang.passkeys || []).map(p => ({ type: "public-key", id: b64ud(p.id) })),
    extensions: { prf: { eval: { first: b64d(zugang.prf_salt) } } } } });
  const r = cred.getClientExtensionResults().prf;
  if (!r || !r.results || !r.results.first) throw new Error("Dieser Browser liefert keinen Passkey-Schlüssel (PRF). Bitte Safari ab iOS/macOS 18 verwenden.");
  return { id: b64ue(cred.rawId), prf: new Uint8Array(r.results.first) };
}

async function einrichten(dkRoh) {
  const salt = zufall(32);
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: zufall(32), rp: { id: rpId, name: "Finanz-Dashboard" },
    user: { id: zufall(16), name: "Finanzen", displayName: "Finanz-Dashboard" },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    timeout: 120000, extensions: { prf: { eval: { first: salt } } } } });
  const ext = cred.getClientExtensionResults().prf;
  if (!ext || ext.enabled === false) throw new Error("Dieser Browser unterstützt keine Verschlüsselung per Passkey. Bitte Safari verwenden.");
  const id = b64ue(cred.rawId);
  let prf = ext.results && ext.results.first;
  if (!prf) {  // manche Geräte liefern den Wert erst bei der ersten Anmeldung
    const r = await passkeyPrf({ passkeys: [{ id }], prf_salt: b64e(salt) });
    prf = r.prf;
  }
  const zugang = { art: "finanz-zugang", v: 1, prf_salt: b64e(salt),
    passkeys: [{ id, angelegt: new Date().toISOString().slice(0, 10), wrapped: await verpacken(await kekAusPrf(prf), dkRoh) }],
    passwort: null };
  const pw = $("#pw-neu").value;
  if (pw) {
    if (pw.length < 12) throw new Error("Das Notfallpasswort braucht mindestens 12 Zeichen.");
    const ps = zufall(16), iter = 600000;
    zugang.passwort = { salt: b64e(ps), iter, wrapped: await verpacken(await kekAusPasswort(pw, ps, iter), dkRoh) };
  }
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(zugang, null, 1)], { type: "application/json" }));
  a.download = "finanz-zugang.json";
  a.click();
  return zugang;
}

// ------------------------------------------------------------------ Ablauf
let ZUGANG = null, DK = null, DATEN = null, versteckt = 0;

async function laden(name) {
  const r = await fetch(name + "?t=" + Date.now(), { cache: "no-store" });
  if (!r.ok) throw new Error(name + " nicht gefunden");
  return r.json();
}
function fehler(t) { $("#fehler").textContent = t || ""; }

async function oeffnenMitDk(dk) {
  DK = dk;
  DATEN = await datenEntschluesseln(DK, await laden("data.enc"));
  $("#sperre").hidden = true; $("#app").hidden = false;
  zeichnen();
}

async function start() {
  const m = location.hash.match(/einrichten=([\w-]+)/);
  if (m) {
    const dk = b64ud(m[1]);
    history.replaceState(null, "", location.pathname);  // Schlüssel aus der Adresszeile entfernen
    $("#sperre-text").textContent = "Einrichtung: Lege einen Passkey an, mit dem nur du das Dashboard öffnen kannst.";
    $("#einrichtung").hidden = false;
    $("#btn-anlegen").onclick = async () => {
      fehler("");
      try {
        await einrichten(dk);
        $("#einrichtung").hidden = true;
        $("#sperre-text").innerHTML = "✅ Passkey angelegt. Jetzt <b>finanz-zugang.json</b> aus Downloads in den Ordner <b>Eingang</b> ziehen. Nach etwa 2 Minuten kannst du das Dashboard hier mit Face ID öffnen.";
        await oeffnenMitDk(dk).catch(() => {});
      } catch (e) { fehler(e.message || String(e)); }
    };
    return;
  }
  try { ZUGANG = await laden("zugang.json"); }
  catch { $("#sperre-text").textContent = "Noch nicht eingerichtet. Bitte auf dem Mac „Handy-Zugang einrichten“ starten."; return; }
  $("#sperre-text").textContent = "Deine Daten sind verschlüsselt. Nur du kannst sie öffnen.";
  $("#btn-faceid").hidden = false;
  if (ZUGANG.passwort) $("#btn-pw-zeigen").hidden = false;
}

$("#btn-faceid").onclick = async () => {
  fehler(""); $("#btn-faceid").disabled = true;
  try {
    const { id, prf } = await passkeyPrf(ZUGANG);
    const eintrag = ZUGANG.passkeys.find(p => p.id === id) || ZUGANG.passkeys[0];
    await oeffnenMitDk(await entpacken(await kekAusPrf(prf), eintrag.wrapped));
  } catch (e) {
    fehler(e.name === "NotAllowedError" ? "Abgebrochen." : e.name === "OperationError" ? "Schlüssel passt nicht." : (e.message || String(e)));
  } finally { $("#btn-faceid").disabled = false; }
};
$("#btn-pw-zeigen").onclick = () => { $("#pw-box").style.display = "flex"; $("#pw").focus(); };
async function mitPasswort() {
  fehler("");
  try {
    const p = ZUGANG.passwort;
    await oeffnenMitDk(await entpacken(await kekAusPasswort($("#pw").value, b64d(p.salt), p.iter), p.wrapped));
    $("#pw").value = "";
  } catch { fehler("Passwort falsch."); }
}
$("#btn-pw").onclick = mitPasswort;
$("#pw").addEventListener("keydown", e => { if (e.key === "Enter") mitPasswort(); });

function sperren() {
  DK = null; DATEN = null;
  document.querySelectorAll("section").forEach(s => s.innerHTML = "");
  $("#app").hidden = true; $("#sperre").hidden = false; fehler("");
}
$("#btn-sperren").onclick = sperren;
$("#btn-neu").onclick = async () => { try { await oeffnenMitDk(DK); } catch (e) { fehler(e.message); } };
// automatisch sperren, wenn die App länger als 5 Minuten im Hintergrund war
document.addEventListener("visibilitychange", () => {
  if (document.hidden) versteckt = Date.now();
  else if (DK && versteckt && Date.now() - versteckt > 5 * 60 * 1000) sperren();
  else if (DK) oeffnenMitDk(DK).catch(e => console.error(e));
});

document.querySelectorAll(".tabs button").forEach(b => b.onclick = () => {
  if (b.dataset.tab === "vermoegen" && DATEN && vAnsicht !== "uebersicht") { vAnsicht = "uebersicht"; zeichneVermoegen(DATEN); }
  document.querySelectorAll(".tabs button").forEach(x => x.setAttribute("aria-selected", x === b));
  document.querySelectorAll("section").forEach(s => s.classList.toggle("on", s.id === b.dataset.tab));
  window.scrollTo({ top: 0 });
});

// ------------------------------------------------------------------ Format
const fEur = new Intl.NumberFormat("de-DE", { style: "currency", currency: "EUR", maximumFractionDigits: 0 });
const eur = v => v == null ? "–" : fEur.format(v);
const pct = (v, n = 1) => v == null ? "–" : v.toLocaleString("de-DE", { minimumFractionDigits: n, maximumFractionDigits: n }) + " %";
const kurz = v => {
  const a = Math.abs(v);
  if (a >= 1e6) return (v / 1e6).toLocaleString("de-DE", { maximumFractionDigits: 1 }) + " Mio";
  if (a >= 1e3) return (v / 1e3).toLocaleString("de-DE", { maximumFractionDigits: 0 }) + " T";
  return v.toLocaleString("de-DE", { maximumFractionDigits: 0 });
};
const monat = m => { const [j, mo] = m.split("-"); return ["Jan", "Feb", "Mär", "Apr", "Mai", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Dez"][+mo - 1] + " " + j.slice(2); };
const datumDe = d => d ? d.slice(8, 10) + "." + d.slice(5, 7) + "." + d.slice(0, 4) : "–";
const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

// ------------------------------------------------------------------ Bausteine
const card = (titel, inhalt, sub = "") => `<div class="card">${titel ? `<h2>${titel}</h2>` : ""}${sub ? `<div class="sub">${sub}</div>` : ""}${inhalt}</div>`;
const kpi = (l, v, d = "") => `<div class="card kpi"><div class="l">${l}</div><div class="v">${v}</div>${d ? `<div class="d">${d}</div>` : ""}</div>`;
const leer = t => `<div class="leer">${t}</div>`;
const legende = serien => serien.length < 2 ? "" : `<div class="legend">${serien.map(s => `<span><i class="sw" style="background:${s.farbe}"></i>${s.name}</span>`).join("")}</div>`;
const delta = (a, b) => (a == null || b == null) ? "" : (a - b >= 0 ? "+" : "−") + eur(Math.abs(a - b)).replace("-", "");

function achse(min, max) {
  if (min === max) { max = min + 1; }
  const roh = (max - min) / 4, p = Math.pow(10, Math.floor(Math.log10(roh)));
  const schritt = [1, 2, 2.5, 5, 10].map(f => f * p).find(s => s >= roh);
  const lo = Math.floor(min / schritt) * schritt, hi = Math.ceil(max / schritt) * schritt;
  const ticks = []; for (let v = lo; v <= hi + schritt / 2; v += schritt) ticks.push(Math.round(v * 100) / 100);
  return { lo, hi, ticks };
}

/* Diagramm: art "linie" | "balken" | "stapel". labels = x-Achse, serien = [{name, farbe, werte}] */
function diagramm(el, { labels, serien, art = "linie", hoehe = 230, xfmt = x => x, nullLinie = true }) {
  const W = Math.max(el.clientWidth, 280), H = hoehe, L = 52, R = 8, T = 8, B = 24;
  const iw = W - L - R, ih = H - T - B, n = labels.length;
  let werte = serien.flatMap(s => s.werte.filter(v => v != null));
  if (art === "stapel") werte = labels.map((_, i) => serien.reduce((a, s) => a + Math.max(0, s.werte[i] || 0), 0));
  let mn = Math.min(...werte), mx = Math.max(...werte);
  if (art !== "linie" || nullLinie) { mn = Math.min(0, mn); mx = Math.max(0, mx); }
  const ax = achse(mn, mx), y = v => T + ih - (v - ax.lo) / (ax.hi - ax.lo) * ih;
  const band = iw / n, x = i => L + (art === "linie" ? (n === 1 ? iw / 2 : i * iw / (n - 1)) : band * (i + 0.5));
  let s = `<svg viewBox="0 0 ${W} ${H}" height="${H}" role="img">`;
  for (const t of ax.ticks) s += `<line x1="${L}" x2="${W - R}" y1="${y(t)}" y2="${y(t)}" stroke="${t === 0 ? css("--t3") : css("--grid")}" stroke-width="1"/>
    <text x="${L - 6}" y="${y(t) + 4}" text-anchor="end">${kurz(t)}</text>`;
  const jede = Math.ceil(n / Math.max(2, Math.floor(iw / 62)));
  labels.forEach((lb, i) => { if (i % jede === 0 || (art === "linie" && i === n - 1 && n < 30)) s += `<text x="${x(i)}" y="${H - 6}" text-anchor="middle">${xfmt(lb)}</text>`; });
  if (art === "linie") {
    for (const se of serien) {
      let d = "", an = false;
      se.werte.forEach((v, i) => { if (v == null) { an = false; return; } d += (an ? "L" : "M") + x(i).toFixed(1) + " " + y(v).toFixed(1); an = true; });
      s += `<path d="${d}" fill="none" stroke="${se.farbe}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;
      if (n <= 16) se.werte.forEach((v, i) => { if (v != null) s += `<circle cx="${x(i)}" cy="${y(v)}" r="3.5" fill="${se.farbe}" stroke="${css("--card")}" stroke-width="2"/>`; });
    }
  } else {
    const gap = 2, innen = Math.min(band * 0.72, 56);
    labels.forEach((_, i) => {
      if (art === "stapel") {
        let basis = 0;
        serien.forEach((se, k) => {
          const v = Math.max(0, se.werte[i] || 0); if (!v) return;
          const y1 = y(basis + v), y0 = y(basis), oben = k === serien.length - 1 || serien.slice(k + 1).every(z => !(z.werte[i] > 0));
          const h = Math.max(0, y0 - y1 - (basis > 0 ? gap : 0));
          s += balkenPfad(x(i) - innen / 2, y1, innen, h, oben ? 4 : 0, se.farbe);
          basis += v;
        });
      } else {
        const bw = (innen - gap * (serien.length - 1)) / serien.length;
        serien.forEach((se, k) => {
          const v = se.werte[i]; if (v == null) return;
          const x0 = x(i) - innen / 2 + k * (bw + gap);
          s += v >= 0 ? balkenPfad(x0, y(v), bw, y(0) - y(v), 4, se.farbe) : balkenPfad(x0, y(0), bw, y(v) - y(0), -4, se.farbe);
        });
      }
    });
  }
  s += `<line class="kreuz" y1="${T}" y2="${T + ih}" stroke="${css("--t3")}" stroke-dasharray="3 3" visibility="hidden"/></svg><div class="tip"></div>`;
  el.innerHTML = s;
  // Hover / Antippen
  const svg = el.querySelector("svg"), tip = el.querySelector(".tip"), kreuz = el.querySelector(".kreuz");
  const zeige = ev => {
    const r = svg.getBoundingClientRect(), px = (ev.clientX - r.left) * W / r.width;
    const i = art === "linie" ? Math.round((px - L) / (n === 1 ? 1 : iw / (n - 1))) : Math.floor((px - L) / band);
    if (i < 0 || i >= n || px < L - 10) { weg(); return; }
    kreuz.setAttribute("x1", x(i)); kreuz.setAttribute("x2", x(i)); kreuz.setAttribute("visibility", art === "linie" ? "visible" : "hidden");
    tip.innerHTML = `<b>${xfmt(labels[i])}</b>` + serien.map(se => `<div class="r"><i class="sw" style="background:${se.farbe}"></i><span>${se.name}</span><span>${eur(se.werte[i])}</span></div>`).join("");
    tip.style.display = "block";
    const tx = x(i) * r.width / W, links = tx > r.width / 2;
    tip.style.left = (links ? tx - tip.offsetWidth - 12 : tx + 12) + "px"; tip.style.top = "4px";
  };
  const weg = () => { tip.style.display = "none"; kreuz.setAttribute("visibility", "hidden"); };
  svg.addEventListener("pointermove", zeige); svg.addEventListener("pointerdown", zeige); svg.addEventListener("pointerleave", weg);
}
function balkenPfad(x, y, w, h, r, farbe) {
  if (h <= 0 || w <= 0) return "";
  const rr = Math.min(Math.abs(r), w / 2, h);
  if (r > 0) return `<path d="M${x} ${y + h}V${y + rr}Q${x} ${y} ${x + rr} ${y}H${x + w - rr}Q${x + w} ${y} ${x + w} ${y + rr}V${y + h}Z" fill="${farbe}"/>`;
  if (r < 0) return `<path d="M${x} ${y}V${y + h - rr}Q${x} ${y + h} ${x + rr} ${y + h}H${x + w - rr}Q${x + w} ${y + h} ${x + w} ${y + h - rr}V${y}Z" fill="${farbe}"/>`;
  return `<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="${farbe}"/>`;
}
function hbalken(items) {
  const mx = Math.max(...items.map(i => Math.abs(i.wert)), 1);
  return `<div class="hb">${items.map(i => `<div class="lab" title="${esc(i.label)}">${esc(i.label)}</div>
    <div><div class="bar" style="width:${Math.abs(i.wert) / mx * 100}%;background:${i.farbe || css("--s1")}"></div></div>
    <div class="val">${eur(i.wert)}${i.zusatz ? ` <span style="color:var(--t3);font-weight:400">${i.zusatz}</span>` : ""}</div>`).join("")}</div>`;
}
function tabelle(kopf, zeilen) {
  return `<div class="scroll"><table><thead><tr>${kopf.map(([t, n]) => `<th class="${n ? "n" : ""}">${t}</th>`).join("")}</tr></thead>
    <tbody>${zeilen.map(z => `<tr>${z.map((v, i) => `<td class="${kopf[i][1] ? "n" : ""}">${v}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}
const plaetze = {};  // Diagramme nach dem Einfügen ins DOM zeichnen
function platz(id, opts) { plaetze[id] = opts; return `<div class="chart" id="${id}"></div>`; }
function diagrammeZeichnen() { for (const [id, o] of Object.entries(plaetze)) { const el = document.getElementById(id); if (el && el.offsetParent !== null) diagramm(el, o); } }

// ------------------------------------------------------------------ Seiten
let zeitraum = 60, herkunft = "12", depotWahl = -1, posWahl = null;
// ------------------------------------------------------------------ Vermögen
let vAnsicht = "uebersicht", kontoWahl = 0;
function zurueck() { return `<button class="link" id="v-zurueck" style="padding:0 0 4px;justify-self:start">‹ Zurück zur Vermögensübersicht</button>`; }
function vZeigen(a) { vAnsicht = a; zeichneVermoegen(DATEN); requestAnimationFrame(diagrammeZeichnen); window.scrollTo({ top: 0 }); }
function tabWechseln(id) { document.querySelector(`.tabs button[data-tab="${id}"]`).click(); }

function zeichneVermoegen(D) {
  if (vAnsicht === "depots") return zeichneDepots(D);
  if (vAnsicht === "konten") return zeichneKonten(D);
  const S1 = css("--s1"), S2 = css("--s2");
  const V = D.vermoegen, t = V.teile, DP = D.depots || [];
  const vk = t["Vorsorge kurzfristig"] || 0, vlg = t["Vorsorge langfristig"] || 0;
  const immoNetto = (t["Immobilien (Wert)"] || 0) + (t.Darlehen || 0);
  const mitEinz = DP.filter(d => d.eingezahlt != null && d.wert != null);
  const einz = mitEinz.reduce((a, d) => a + d.eingezahlt, 0), gew = mitEinz.reduce((a, d) => a + (d.wert - d.eingezahlt), 0);
  const nKonten = V.konten.filter(k => k.art === "giro" || k.art === "tagesgeld").length;
  const vl = V.verlauf.slice(-zeitraum - 1);
  let h = `<div class="card hero"><div class="l">Nettovermögen</div><div class="v">${eur(V.netto)}</div>
    <div class="d">${delta(V.netto, V.netto_vorjahr) ? delta(V.netto, V.netto_vorjahr) + " zum Vorjahr" : ""}</div></div>`;
  h += `<div class="grid kpis">
    <button class="card kpi kachel" data-ziel="depots"><div class="l">Depot & Kapitalanlage ›</div><div class="v">${eur(t.Depot)}</div>
      <div class="d">${mitEinz.length ? `eingezahlt ${eur(einz)} · Gewinn ${eur(gew)}` : DP.length + " Depots & Anlagen"}</div></button>
    <button class="card kpi kachel" data-ziel="konten"><div class="l">Konten ›</div><div class="v">${eur(t.Konten)}</div>
      <div class="d">${nKonten} Konten${V.sparquote != null ? " · Sparquote " + pct(V.sparquote) : ""}</div></button>
    <button class="card kpi kachel" data-ziel="immobilien"><div class="l">Immobilien netto ›</div><div class="v">${eur(immoNetto)}</div>
      <div class="d">Wert ${kurz(t["Immobilien (Wert)"] || 0)} € − Darlehen ${kurz(-(t.Darlehen || 0))} €</div></button>
    <button class="card kpi kachel" data-ziel="vorsorge"><div class="l">Vorsorge ›</div><div class="v">${eur(vk + vlg)}</div>
      <div class="d">kurzfristig verfügbar ${eur(vk)}<br>langfristig ${eur(vlg)}</div></button></div>`;
  h += `<div class="grid two">` + card(`Nettovermögen im Verlauf <span class="seg" id="seg">${[[12, "1J"], [36, "3J"], [60, "5J"], [120, "10J"]].map(([m, l]) => `<button data-m="${m}" aria-pressed="${m === zeitraum}">${l}</button>`).join("")}</span>`,
      vl.length ? legende([{ name: "Nettovermögen", farbe: S1 }, { name: "Depot & Konten", farbe: css("--s3") }, { name: "Immobilien netto", farbe: css("--s4") }])
        + platz("c-netto", { labels: vl.map(p => p.d.slice(0, 7)), xfmt: monat, nullLinie: false, serien: [
          { name: "Nettovermögen", farbe: S1, werte: vl.map(p => p.netto) },
          { name: "Depot & Konten", farbe: css("--s3"), werte: vl.map(p => (p.depot || 0) + (p.konten || 0)) },
          { name: "Immobilien netto", farbe: css("--s4"), werte: vl.map(p => (p.immo || 0) + (p.darlehen || 0)) }] })
        : leer("Noch keine Daten – Dokumente in den Ordner „Eingang“ legen."),
      "Depots vor dem ersten Kontoauszug aus den Transaktionen geschätzt · Immobilien ab Kauf mit Tilgung")
    + card("Zusammensetzung heute", hbalken([["Depot", "Depot & Kapitalanlage", t.Depot], ["Konten", "Konten", t.Konten], ["netto", "Immobilien netto", immoNetto],
        ["wert", "Immobilien (Wert)", t["Immobilien (Wert)"]], ["darlehen", "Darlehen", t.Darlehen], ["vorsorge", "Vorsorge", vk + vlg]]
        .filter(x => x[2]).map(([, l, w]) => ({ label: l, wert: w, farbe: w < 0 ? S2 : S1 })))) + `</div>`;
  h += `<div class="grid two">` + card("Privat: Einnahmen und Ausgaben",
      V.cashflow.length ? legende([{ name: "Einnahmen", farbe: S1 }, { name: "Ausgaben", farbe: S2 }]) + platz("c-cf", { labels: V.cashflow.map(c => c.m), art: "balken", xfmt: monat, serien: [{ name: "Einnahmen", farbe: S1, werte: V.cashflow.map(c => c.ein) }, { name: "Ausgaben", farbe: S2, werte: V.cashflow.map(c => c.aus) }] }) : leer("Kommt mit dem ersten Kontoumsatz-Export (CSV)."))
    + card("Ausgaben nach Kategorie", V.kategorien.length ? hbalken(V.kategorien.map(k => ({ label: k.k, wert: k.b }))) : leer("–"), "letzte 12 Monate, privat") + `</div>`;
  $("#vermoegen").innerHTML = h;
  $("#seg")?.addEventListener("click", e => { const m = +e.target.dataset.m; if (m) { zeitraum = m; zeichneVermoegen(D); requestAnimationFrame(diagrammeZeichnen); } });
  document.querySelectorAll(".kachel").forEach(b => b.onclick = () => {
    const z = b.dataset.ziel;
    if (z === "immobilien") tabWechseln("immobilien");
    else if (z === "vorsorge") { vZeigen("konten"); setTimeout(() => document.getElementById("v-vorsorge")?.scrollIntoView({ behavior: "smooth" }), 50); }
    else vZeigen(z);
  });
}

function zeichneKonten(D) {
  const S1 = css("--s1"), S2 = css("--s2");
  const K = D.vermoegen.konten;
  const gruppen = [["Konten", K.filter(k => k.art === "giro" || k.art === "tagesgeld"), "v-konten"],
                   ["Vorsorge – kurzfristig verfügbar", K.filter(k => k.art === "vorsorge" && k.vorsorge === "kurzfristig"), "v-vorsorge"],
                   ["Vorsorge – langfristig", K.filter(k => k.art === "vorsorge" && k.vorsorge !== "kurzfristig"), "v-vorsorge-l"]];
  let h = zurueck();
  for (const [titel, liste, id] of gruppen) {
    if (!liste.length) continue;
    liste.sort((a, b) => (b.saldo || 0) - (a.saldo || 0));
    const summe = liste.reduce((a, k) => a + (k.saldo || 0), 0);
    h += `<div class="card" id="${id}"><h2>${titel} <span style="float:right">${eur(summe)}</span></h2>` + tabelle([["Konto"], ["Zins", 1], ["Stand", 1], ["vom", 1]],
      liste.map(k => [esc(k.name) + (k.bewegungen.length || k.verlauf.length > 1 ? " ›" : ""), k.zins != null ? pct(k.zins) + " p.a." : "", eur(k.saldo), datumDe(k.datum)])) + `</div>`;
  }
  const det = K.filter(k => k.art !== "depot" && (k.bewegungen.length || k.verlauf.length > 1));
  if (det.length) {
    if (kontoWahl >= det.length) kontoWahl = 0;
    const k = det[kontoWahl];
    h += `<div class="card" id="v-detail"><h2>Entwicklung je Konto</h2><div class="seg wrap" id="seg-konto">${det.map((x, i) =>
      `<button data-i="${i}" aria-pressed="${i === kontoWahl}">${esc(x.name)}</button>`).join("")}</div>`;
    if (k.verlauf.length > 1) h += `<h2 style="margin-top:14px">Kontostand</h2>` + platz("c-ks", { labels: k.verlauf.map(x => x.d), xfmt: d => datumDe(d).slice(3), nullLinie: false,
      serien: [{ name: "Kontostand", farbe: S1, werte: k.verlauf.map(x => x.w) }] });
    if (k.bewegungen.length) {
      const jahre = {};
      k.bewegungen.forEach(b => { const j = b.m.slice(0, 4); jahre[j] = jahre[j] || { ein: 0, aus: 0, n: 0 }; jahre[j].ein += b.ein; jahre[j].aus += b.aus; });
      const JL = Object.keys(jahre).sort();
      h += `<h2 style="margin-top:14px">Ein- und Ausgänge pro Jahr</h2>` + legende([{ name: "Eingänge", farbe: S1 }, { name: "Ausgänge", farbe: S2 }])
        + platz("c-kj", { labels: JL, art: "balken", serien: [{ name: "Eingänge", farbe: S1, werte: JL.map(j => jahre[j].ein) }, { name: "Ausgänge", farbe: S2, werte: JL.map(j => jahre[j].aus) }] })
        + tabelle([["Jahr"], ["Eingänge", 1], ["Ausgänge", 1], ["Saldo", 1]], JL.slice().reverse().map(j => [j, eur(jahre[j].ein), eur(jahre[j].aus), eur(jahre[j].ein - jahre[j].aus)]));
      const M = k.bewegungen.slice(-24);
      h += `<h2 style="margin-top:14px">Letzte 24 Monate</h2>` + platz("c-km", { labels: M.map(b => b.m), xfmt: monat, art: "balken",
        serien: [{ name: "Eingänge", farbe: S1, werte: M.map(b => b.ein) }, { name: "Ausgänge", farbe: S2, werte: M.map(b => b.aus) }] });
    } else h += leer("Für Ein- und Ausgänge die Umsätze dieses Kontos als CSV in den Eingang legen.");
    h += `<div class="sub" style="margin-top:8px">ohne Umbuchungen zwischen eigenen Konten</div></div>`;
  }
  $("#vermoegen").innerHTML = h;
  $("#v-zurueck").onclick = () => vZeigen("uebersicht");
  document.querySelectorAll("#seg-konto button").forEach(b => b.onclick = () => { kontoWahl = +b.dataset.i; zeichneKonten(D); requestAnimationFrame(diagrammeZeichnen); });
  const namen = [...document.querySelectorAll("#seg-konto button")].map(b => b.textContent);
  document.querySelectorAll("#vermoegen .card[id^=v-k], #vermoegen .card[id^=v-v]").forEach(c => c.querySelectorAll("tbody tr").forEach(tr => {
    const i = namen.indexOf(tr.cells[0].textContent.replace(/ ›$/, ""));
    if (i < 0) return;
    tr.classList.add("klick");
    tr.onclick = () => { kontoWahl = i; zeichneKonten(D); requestAnimationFrame(diagrammeZeichnen); document.getElementById("v-detail").scrollIntoView({ behavior: "smooth" }); };
  }));
}

function zeichneDepots(D) {
  const S1 = css("--s1"), S2 = css("--s2"), S3 = css("--s3"), S4 = css("--s4");
  const L = D.depots || [];
  let h = zurueck();
  if (!L.length) { $("#vermoegen").innerHTML = h + card("", leer("Noch keine Depotdaten.")); $("#v-zurueck").onclick = () => vZeigen("uebersicht"); return; }
  if (depotWahl >= L.length) depotWahl = -1;
  const gesamt = L.reduce((a, d) => a + (d.wert || 0), 0);
  const mitE = L.filter(d => d.eingezahlt != null && d.wert != null);
  const einz = mitE.reduce((a, d) => a + d.eingezahlt, 0), gew = mitE.reduce((a, d) => a + d.wert - d.eingezahlt, 0);
  const ertr = L.reduce((a, d) => a + (d.ertraege || 0), 0), real = L.reduce((a, d) => a + (d.realisiert || 0), 0);
  const dp = depotWahl >= 0 ? L[depotWahl] : null;
  h += `<div class="grid kpis">
    ${kpi(dp ? "Depotwert" : "Alle Depots", eur(dp ? dp.wert : gesamt), dp ? (dp.datum ? "Stand " + datumDe(dp.datum) : "") : L.length + " Depots & Anlagen")}
    ${kpi("Eingezahlt (netto)", eur(dp ? dp.eingezahlt : mitE.length ? einz : null), dp ? "Einzahlungen minus Auszahlungen" : `bei ${mitE.length} Depots mit bekannter Einzahlung`)}
    ${kpi("Gewinn", eur(dp ? dp.gewinn : mitE.length ? gew : null), (dp ? dp.eingezahlt : einz) ? pct((dp ? dp.gewinn : gew) / (dp ? dp.eingezahlt : einz) * 100) + " auf eingezahlt" : "")}
    ${dp && dp.rendite_pa != null ? kpi("Rendite p.a.", pct(dp.rendite_pa)) : kpi("Erträge gesamt", eur(dp ? dp.ertraege : ertr), "Dividenden und Zinsen, realisiert " + eur(dp ? dp.realisiert : real))}</div>`;
  h += `<div class="card" style="padding:10px 12px"><div class="seg wrap" id="seg-depot"><button data-i="-1" aria-pressed="${depotWahl === -1}">Alle · ${kurz(gesamt)} €</button>${L.map((d, i) =>
    `<button data-i="${i}" aria-pressed="${i === depotWahl}">${esc(d.name)} · ${kurz(d.wert || 0)} €</button>`).join("")}</div></div>`;
  if (!dp) {
    // alle Positionen über alle Depots, nach Größe
    const alle = [];
    L.forEach(d => {
      if (d.positionen.length) d.positionen.forEach(p => alle.push({ ...p, depot: d.name }));
      else if (d.wert) alle.push({ name: d.name, depot: d.name, wert: d.wert, investiert: d.eingezahlt, gewinn: d.gewinn });
    });
    alle.sort((a, b) => (b.wert || 0) - (a.wert || 0));
    h += card(`Alle Positionen (${alle.length}) nach Größe`, tabelle([["Position"], ["Wert", 1], ["Anteil", 1], ["Gewinn", 1], ["Depot"]],
      alle.map(p => [esc(p.name), eur(p.wert), pct((p.wert || 0) / gesamt * 100), eur(p.gewinn), `<span style="color:var(--t3)">${esc(p.depot)}</span>`])),
      "Gesamtrisiko: wo am meisten Geld steckt – unabhängig vom Depot");
    h += card("Depots im Überblick", tabelle([["Depot"], ["Wert", 1], ["Eingezahlt", 1], ["Gewinn", 1], ["Stand", 1]],
      L.map(d => [esc(d.name), eur(d.wert), eur(d.eingezahlt), eur(d.gewinn), datumDe(d.datum)])));
  } else {
    const J = dp.jahre || [];
    if (J.length) h += card("Pro Jahr nach Buchungsdatum", legende([{ name: "Einzahlungen", farbe: S1 }, { name: "Käufe", farbe: S4 }, { name: "Erträge", farbe: S3 }, { name: "Auszahlungen", farbe: S2 }])
      + platz("c-dpj", { labels: J.map(j => String(j.jahr)), art: "balken", serien: [
          { name: "Einzahlungen", farbe: S1, werte: J.map(j => j.einzahlung) }, { name: "Käufe", farbe: S4, werte: J.map(j => j.kauf + j.wiederanlage) },
          { name: "Erträge", farbe: S3, werte: J.map(j => j.ertrag) }, { name: "Auszahlungen", farbe: S2, werte: J.map(j => j.auszahlung) }] })
      + tabelle([["Jahr"], ["Einzahlungen", 1], ["Auszahlungen", 1], ["Käufe", 1], ["Wiederanlage", 1], ["Verkäufe", 1], ["Erträge", 1], ["Gebühren", 1], ["Steuern", 1], ["Buchungen", 1]],
          J.slice().reverse().map(j => [j.jahr, eur(j.einzahlung), eur(j.auszahlung), eur(j.kauf), eur(j.wiederanlage), eur(j.verkauf), eur(j.ertrag), eur(j.gebuehr), eur(j.steuer), j.anzahl])));
    const EV = dp.einzahlungen_verlauf || [], WG = Object.fromEntries((dp.wert_geschaetzt || []).map(x => [x.m, x.w]));
    if (EV.length > 1) {
      const wv = Object.fromEntries((dp.wert_verlauf || []).map(x => [x.d.slice(0, 7), x.w]));
      h += card("Eingezahlt und Depotwert im Verlauf", legende([{ name: "Eingezahlt (netto)", farbe: S4 }, { name: "Depotwert (geschätzt)", farbe: S1 }])
        + platz("c-dpv", { labels: EV.map(x => x.m), xfmt: monat, nullLinie: false, serien: [
            { name: "Eingezahlt (netto)", farbe: S4, werte: EV.map(x => x.netto) },
            { name: "Depotwert (geschätzt)", farbe: S1, werte: EV.map(x => wv[x.m] ?? WG[x.m] ?? null) }] }),
        "Depotwert = Bestand × letzter bekannter Kurs aus den Transaktionen, ab Kontoauszug echte Stände");
    }
    if ((dp.perf || []).length > 2) h += card("Wertentwicklung seit Kauf (%)", platz("c-perf", { labels: dp.perf.map(x => x.d), xfmt: d => datumDe(d).slice(3), nullLinie: true,
      serien: [{ name: "Wertentwicklung %", farbe: S3, werte: dp.perf.map(x => x.p) }] }), "laut Depotbank");
    const P = dp.positionen || [];
    if (P.length) h += card(`Positionen (${P.length})`, tabelle([["Wertpapier"], ["Stück", 1], ["Investiert", 1], ["Wert", 1], ["Gewinn", 1], ["Rendite", 1]],
        P.map(p => [esc(p.name), p.stueck != null ? (+p.stueck).toLocaleString("de-DE", { maximumFractionDigits: 4 }) : "", eur(p.investiert), eur(p.wert), eur(p.gewinn),
          p.rendite != null ? pct(p.rendite) : p.rendite_pa != null ? pct(p.rendite_pa) + " p.a." : ""])) + `<div id="kurs-box"></div>`,
        (dp.quelle_positionen ? "Quelle: " + dp.quelle_positionen + " · " : "") + "Zeile antippen für Kursverlauf");
  }
  $("#vermoegen").innerHTML = h;
  $("#v-zurueck").onclick = () => vZeigen("uebersicht");
  document.querySelectorAll("#seg-depot button").forEach(b => b.onclick = () => { depotWahl = +b.dataset.i; zeichneDepots(D); requestAnimationFrame(diagrammeZeichnen); });
  if (dp && (dp.positionen || []).length) {
    const zeilenEls = document.querySelectorAll("#vermoegen .card:last-of-type tbody tr");
    zeilenEls.forEach((tr, i) => {
      tr.classList.add("klick");
      tr.onclick = () => {
        zeilenEls.forEach(x => x.classList.remove("aktiv")); tr.classList.add("aktiv");
        const p = dp.positionen[i], k = p.kurse || [], box = $("#kurs-box");
        if (k.length < 2) { box.innerHTML = leer("Für diese Position gibt es zu wenige Kurse für einen Verlauf."); return; }
        box.innerHTML = `<h2 style="margin-top:14px">${esc(p.name)} – Kursverlauf</h2><div class="chart" id="c-kurs"></div>`;
        plaetze["c-kurs"] = { labels: k.map(x => x.d), xfmt: d => datumDe(d).slice(3), nullLinie: false, serien: [{ name: "Kurs", farbe: S1, werte: k.map(x => x.k) }] };
        diagramm($("#c-kurs"), plaetze["c-kurs"]);
      };
    });
  }
}

function zeichnen() {
  for (const k in plaetze) delete plaetze[k];
  const D = DATEN, S1 = css("--s1"), S2 = css("--s2"), S3 = css("--s3"), S4 = css("--s4");
  $("#stand").textContent = "Stand " + datumDe(D.stand.slice(0, 10)) + ", " + D.stand.slice(11, 16) + " Uhr";

  // ---------- Vermögen (Übersicht oder Unterseite Konten / Depots)
  zeichneVermoegen(D);

  // ---------- Geschäft
  const G = D.geschaeft, gj = G.jahre, letzt = gj[gj.length - 1], vorj = gj[gj.length - 2];
  let h = "";
  if (!gj.length && !G.bwa.length && !G.cashflow.length) h = card("", leer("Noch keine Geschäftszahlen. EÜR, GuV, Jahresabschlüsse oder BWAs in den Eingang legen.<br>Kontoumsätze des Geschäftskontos in einen Unterordner „Geschäft“ im Eingang legen."));
  else {
    const teil = letzt && letzt.monate < 12, vgl = vorj && !teil;
    if (letzt) h += `<div class="grid kpis">
      ${kpi("Umsatz " + letzt.jahr, eur(letzt.umsatz), teil ? `bis jetzt, aus ${letzt.monate} BWA-Monaten` : vgl ? delta(letzt.umsatz, vorj.umsatz) + " zu " + vorj.jahr : "")}
      ${kpi("Gewinn " + letzt.jahr, eur(letzt.gewinn), teil && vorj ? `Hochrechnung ${eur(letzt.gewinn / letzt.monate * 12)} (Vorjahr ${eur(vorj.gewinn)})` : vgl ? delta(letzt.gewinn, vorj.gewinn) + " zu " + vorj.jahr : "")}
      ${kpi("Kosten " + letzt.jahr, eur(letzt.kosten))}
      ${kpi("Gewinnmarge", pct(letzt.marge), letzt.quelle === "BWA" ? "vorläufig (BWA)" : "lt. Abschluss")}</div>`;
    if (gj.length) h += card("Umsatz, Kosten und Gewinn pro Jahr", legende([{ name: "Umsatz", farbe: S1 }, { name: "Kosten", farbe: S2 }, { name: "Gewinn", farbe: S3 }])
      + platz("c-gj", { labels: gj.map(j => j.monate < 12 ? `${j.jahr} (${j.monate} M.)` : String(j.jahr)), art: "balken", serien: [{ name: "Umsatz", farbe: S1, werte: gj.map(j => j.umsatz) }, { name: "Kosten", farbe: S2, werte: gj.map(j => j.kosten) }, { name: "Gewinn", farbe: S3, werte: gj.map(j => j.gewinn) }] }));
    const zeilen2 = [];
    if (G.bwa.length) zeilen2.push(card("Monatsergebnis (BWA)", legende([{ name: "Umsatz", farbe: S1 }, { name: "Ergebnis", farbe: S3 }])
      + platz("c-bwa", { labels: G.bwa.map(b => b.m), xfmt: monat, art: "balken", serien: [{ name: "Umsatz", farbe: S1, werte: G.bwa.map(b => b.umsatz) }, { name: "Ergebnis", farbe: S3, werte: G.bwa.map(b => b.gewinn) }] })));
    if (G.cashflow.length) zeilen2.push(card("Geschäftskonto: Ein- und Auszahlungen", legende([{ name: "Eingänge", farbe: S1 }, { name: "Ausgänge", farbe: S2 }])
      + platz("c-gcf", { labels: G.cashflow.map(c => c.m), xfmt: monat, art: "balken", serien: [{ name: "Eingänge", farbe: S1, werte: G.cashflow.map(c => c.ein) }, { name: "Ausgänge", farbe: S2, werte: G.cashflow.map(c => c.aus) }] })));
    if (zeilen2.length) h += `<div class="grid ${zeilen2.length > 1 ? "two" : ""}">${zeilen2.join("")}</div>`;
    const HK = { "12": G.herkunft_12m || [], [String(new Date().getFullYear())]: G.herkunft_jahr || [], [String(new Date().getFullYear() - 1)]: G.herkunft_vorjahr || [] };
    if ((G.herkunft_12m || []).length) {
      h += `<div class="grid two">` + card(`Einnahmen nach Auftraggeber <span class="seg" id="seg-hk">${Object.keys(HK).filter(k => HK[k].length).map(k => `<button data-k="${k}" aria-pressed="${k === herkunft}">${k === "12" ? "12 Mon." : k}</button>`).join("")}</span>`,
          `<div id="hk-liste"></div>`, "Geschäftskonto, ohne Umbuchungen")
        + card("Geschäftliche Ausgaben nach Kategorie", (G.kosten_kategorien || []).length ? hbalken(G.kosten_kategorien.map(k => ({ label: k.k, wert: k.b, farbe: S2 }))) : leer("–"), "letzte 12 Monate") + `</div>`;
    }
    if (gj.length) h += card("Jahresübersicht", tabelle([["Jahr"], ["Umsatz", 1], ["Kosten", 1], ["Gewinn", 1], ["Steuerl. Gewinn", 1], ["Marge", 1], ["Quelle"]],
      gj.slice().reverse().map(j => [j.jahr, eur(j.umsatz), eur(j.kosten), eur(j.gewinn), eur(j.steuerlicher_gewinn), pct(j.marge), j.quelle === "BWA" ? `BWA (${j.monate} Mon.)` : j.quelle])));
  }
  $("#geschaeft").innerHTML = h;
  const hkZeigen = () => {
    const el = $("#hk-liste"); if (!el) return;
    const HKd = { "12": G.herkunft_12m || [], [String(new Date().getFullYear())]: G.herkunft_jahr || [], [String(new Date().getFullYear() - 1)]: G.herkunft_vorjahr || [] };
    const l = HKd[herkunft] || [];
    el.innerHTML = l.length ? hbalken(l.map(x => ({ label: x.name, wert: x.betrag, zusatz: pct(x.anteil, 0) }))) : leer("Keine Einnahmen im Zeitraum.");
    document.querySelectorAll("#seg-hk button").forEach(b => b.setAttribute("aria-pressed", b.dataset.k === herkunft));
  };
  $("#seg-hk")?.addEventListener("click", e => { if (e.target.dataset.k) { herkunft = e.target.dataset.k; hkZeigen(); } });
  hkZeigen();

  // ---------- Immobilien
  const I = D.immobilien, O = I.objekte;
  if (!O.length) $("#immobilien").innerHTML = card("", leer("Noch keine Immobilie erkannt. Kaufverträge, Darlehensverträge und Mietverträge in den Eingang legen."));
  else {
    const sum = k => O.reduce((a, o) => a + (o[k] || 0), 0);
    const sumV = k => O.filter(o => o.nutzung !== "selbst").reduce((a, o) => a + (o[k] || 0), 0);
    h = `<div class="grid kpis">
      ${kpi("Gesamtwert", eur(sum("wert")), O.length + (O.length === 1 ? " Objekt" : " Objekte") + (O.some(o => o.anteil < 1) ? " · dein Anteil" : ""))}
      ${kpi("Restschuld", eur(sum("restschuld")), sum("wert") ? "Beleihung " + pct(sum("restschuld") / sum("wert") * 100, 0) : "")}
      ${kpi("Eigenkapital", eur(sum("ek")))}
      ${kpi("Kaltmiete / Monat", eur(sum("miete")), eur(sum("miete") * 12) + " im Jahr")}
      ${kpi("Cashflow / Monat", eur(sumV("cashflow")), "vermietete Objekte, nach Rate und Kosten, vor Steuern")}</div>`;
    h += I.hinweise.map(x => `<div class="warn">${esc(x)}</div>`).join("");
    h += card("Wert je Objekt: Restschuld und Eigenkapital", legende([{ name: "Restschuld", farbe: S2 }, { name: "Eigenkapital", farbe: S1 }])
      + platz("c-obj", { labels: O.map(o => o.name), art: "stapel", hoehe: 250, xfmt: n => n.length > 14 ? n.slice(0, 13) + "…" : n,
        serien: [{ name: "Restschuld", farbe: S2, werte: O.map(o => o.restschuld) }, { name: "Eigenkapital", farbe: S1, werte: O.map(o => Math.max(0, o.ek)) }] }));
    const opt = `<select id="obj-wahl"><option value="">Alle Objekte</option>${O.map(o => `<option value="${o.id}">${esc(o.name)}</option>`).join("")}</select>`;
    h += card(`Wert und Restschuld im Zeitverlauf <span style="float:right">${opt}</span>`, `<div id="tv-legende">${legende([{ name: "Wert", farbe: S1 }, { name: "Restschuld", farbe: S2 }])}</div><div class="chart" id="c-tv"></div>`,
      `Wert ab letzter Bewertung mit ${pct(I.wertsteigerung * 100, 0)} p.a. fortgeschrieben · Restschuld nach Tilgungsplan`);
    h += `<div class="grid objekte">${O.map(o => `<div class="card obj"><h2>${esc(o.name)}</h2><div class="adr">${esc(o.adresse)}${o.anteil && o.anteil < 1 ? ` · Anteil ${pct(o.anteil * 100, 0)}${o.mit ? " (mit " + esc(o.mit) + ")" : ""}` : ""}${o.nutzung === "selbst" ? " · selbst genutzt" : ""}${o.status && /bau/i.test(o.status) ? " · im Bau" : ""}</div><dl>
      <dt>Wert</dt><dd>${eur(o.wert)}</dd><dt>Restschuld</dt><dd>${eur(o.restschuld)}</dd><dt>Eigenkapital</dt><dd>${eur(o.ek)}</dd>
      <dt>Kaltmiete / Monat</dt><dd>${eur(o.miete)}</dd><dt>Rate / Monat</dt><dd>${eur(o.rate)}</dd><dt>Kosten / Jahr</dt><dd>${eur(o.kosten)}</dd>
      <dt>Cashflow / Monat</dt><dd>${eur(o.cashflow)}</dd><dt>Brutto- / Nettorendite</dt><dd>${pct(o.brutto)} / ${pct(o.netto)}</dd>
      <dt>Zinsbindung bis</dt><dd>${o.zinsbindung ? o.zinsbindung.slice(5, 7) + "/" + o.zinsbindung.slice(0, 4) : "–"}</dd>
      <dt>Kaufpreis</dt><dd>${eur(o.kaufpreis)}</dd>
      <dt>Kauf</dt><dd>${o.kaufdatum ? datumDe(o.kaufdatum) : o.kaufdatum_geschaetzt ? "ca. " + o.kaufdatum_geschaetzt.slice(5, 7) + "/" + o.kaufdatum_geschaetzt.slice(0, 4) : "–"}</dd>
      <dt>Wertbasis</dt><dd>${esc(o.wertquelle || "–")}</dd></dl>
      ${o.fehlt ? `<div class="fehlt">Fehlt noch: ${esc(o.fehlt)}</div>` : ""}</div>`).join("")}</div>`;
    $("#immobilien").innerHTML = h;
    const tv = () => {
      const id = $("#obj-wahl").value, v = id ? O.find(o => o.id == id).verlauf : I.verlauf;
      plaetze["c-tv"] = { labels: v.map(p => String(p.j)), serien: [{ name: "Wert", farbe: S1, werte: v.map(p => p.wert) }, { name: "Restschuld", farbe: S2, werte: v.map(p => p.rs) }] };
      const el = $("#c-tv"); if (el.offsetParent !== null) diagramm(el, plaetze["c-tv"]);
    };
    $("#obj-wahl").onchange = tv; tv();
  }

  // ---------- Steuern
  const ST = D.steuern.jahre, STV = ST.filter(s => s.veranlagt), STB = ST.filter(s => s.betrieb);
  if (!ST.length) $("#steuern").innerHTML = card("", leer("Noch keine Steuerdaten. Bescheide, Erklärungen und Besteuerungsgrundlagen in den Eingang legen."));
  else {
    h = "";
    const lb = STB[STB.length - 1], vb = STB[STB.length - 2];
    if (lb) h += `<div class="grid kpis">
      ${kpi("Einkünfte Gewerbebetrieb " + lb.jahr, eur(lb.gewerbe), vb && vb.gewerbe != null && lb.gewerbe != null ? delta(lb.gewerbe, vb.gewerbe) + " zu " + vb.jahr : lb.quelle)}
      ${kpi("Gewerbesteuer " + lb.jahr, eur(lb.gewerbesteuer), lb.gewst_messbetrag != null ? "Messbetrag " + eur(lb.gewst_messbetrag) + " (auf ESt anrechenbar)" : "")}
      ${kpi("Umsatzsteuer-Zahllast " + lb.jahr, eur(lb.ust_zahllast), lb.ust_steuerfrei != null ? "steuerfreie Umsätze " + eur(lb.ust_steuerfrei) : "")}
      ${STV.length ? kpi("Einkommensteuer " + STV[STV.length - 1].jahr, eur(STV[STV.length - 1].gesamt), "Durchschnittssatz " + pct(STV[STV.length - 1].satz)) : kpi("Einkommensteuer", "–", "kommt mit dem ersten ESt-Bescheid")}</div>`;
    if (STB.length) h += `<div class="grid two">` + card("Einkünfte aus Gewerbebetrieb",
        platz("c-gew", { labels: STB.map(s => String(s.jahr)), art: "balken", serien: [{ name: "Einkünfte", farbe: S1, werte: STB.map(s => s.gewerbe) }] }), "steuerlich, laut Feststellung / Anlage G")
      + card("Gewerbe- und Umsatzsteuer", legende([{ name: "Gewerbesteuer", farbe: S2 }, { name: "Umsatzsteuer-Zahllast", farbe: S4 }])
        + platz("c-gst", { labels: STB.map(s => String(s.jahr)), art: "balken", serien: [{ name: "Gewerbesteuer", farbe: S2, werte: STB.map(s => s.gewerbesteuer) }, { name: "Umsatzsteuer-Zahllast", farbe: S4, werte: STB.map(s => s.ust_zahllast) }] })) + `</div>`;
    if (STV.length) h += card("Einkommensteuer pro Jahr", legende([{ name: "Einkommensteuer", farbe: S1 }, { name: "Solidaritätszuschlag", farbe: S3 }, { name: "Kirchensteuer", farbe: S4 }])
        + platz("c-st", { labels: STV.map(s => String(s.jahr)), art: "stapel", serien: [{ name: "Einkommensteuer", farbe: S1, werte: STV.map(s => s.einkommensteuer) }, { name: "Solidaritätszuschlag", farbe: S3, werte: STV.map(s => s.soli) }, { name: "Kirchensteuer", farbe: S4, werte: STV.map(s => s.kirchensteuer) }] }));
    const KAP = ST.filter(s => s.kap_ertrag != null);
    if (KAP.length) h += card("Kapitalerträge aus Fondsdepots", tabelle([["Jahr"], ["Steuerpflichtiger Ertrag", 1], ["Abgeltungsteuer inkl. Soli/KiSt", 1]],
      KAP.slice().reverse().map(s => [s.jahr, eur(s.kap_ertrag), eur(s.abgeltung)])), "bereits von der Bank einbehalten (u.a. Vorabpauschale)");
    h += card("Übersicht", tabelle([["Jahr"], ["Quelle"], ["Einkünfte Gewerbe", 1], ["GewSt-Messbetrag", 1], ["Gewerbesteuer", 1], ["USt-Zahllast", 1], ["zvE", 1], ["ESt gesamt", 1], ["Erst./Nachz.", 1]],
      ST.filter(s => s.betrieb || s.veranlagt).slice().reverse().map(s => [s.jahr, s.quelle, eur(s.gewerbe), eur(s.gewst_messbetrag), eur(s.gewerbesteuer), eur(s.ust_zahllast), eur(s.zve), eur(s.gesamt), eur(s.abrechnung)])));
    $("#steuern").innerHTML = h;
  }

  // ---------- Fuß
  const P = D.dokumente.pruefen;
  $("#fuss").innerHTML = `${D.dokumente.ok} Dokumente verarbeitet.` + (P.length ? `<details><summary>${P.length} Datei(en) im Ordner „Prüfen“</summary>${tabelle([["Datei"], ["Grund"]], P.map(p => [esc(p.datei), esc(p.grund)]))}</details>` : "");
  requestAnimationFrame(diagrammeZeichnen);
}
document.querySelectorAll(".tabs button").forEach(b => b.addEventListener("click", () => requestAnimationFrame(diagrammeZeichnen)));
let rz; window.addEventListener("resize", () => { clearTimeout(rz); rz = setTimeout(() => DATEN && diagrammeZeichnen(), 150); });
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => DATEN && zeichnen());

start();
