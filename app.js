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

let bereich = "privat";
const letzterTab = { privat: "vermoegen", geschaeft: "g-abschluss" };
document.querySelectorAll(".tabs button").forEach(b => b.onclick = () => {
  if (b.dataset.tab === "vermoegen" && DATEN && vAnsicht !== "uebersicht") { vAnsicht = "uebersicht"; zeichneVermoegen(DATEN); }
  if (b.dataset.tab === "immobilien" && DATEN && immoDetail != null && b.getAttribute("aria-selected") === "true") { immoDetail = null; zeichneImmobilien(DATEN); }
  const gruppe = b.closest(".tabs");
  gruppe.querySelectorAll("button").forEach(x => x.setAttribute("aria-selected", x === b));
  letzterTab[bereich] = b.dataset.tab;
  document.querySelectorAll("section").forEach(s => s.classList.toggle("on", s.id === b.dataset.tab));
  window.scrollTo({ top: 0 });
});
function bereichWechseln(neu) {
  bereich = neu;
  document.querySelectorAll(".bereiche button").forEach(x => x.setAttribute("aria-selected", x.dataset.bereich === neu));
  $("#tabs-privat").hidden = neu !== "privat"; $("#tabs-geschaeft").hidden = neu !== "geschaeft"; $("#g-kopf").hidden = neu !== "geschaeft";
  document.querySelector(`.tabs button[data-tab="${letzterTab[neu]}"]`).click();
}
document.querySelectorAll(".bereiche button").forEach(b => b.onclick = () => bereichWechseln(b.dataset.bereich));

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
  const sicht = serien.filter(se => !se.nurTip);
  let werte = sicht.flatMap(s => s.werte.filter(v => v != null));
  if (art === "stapel") werte = labels.flatMap((_, i) => [sicht.reduce((a, s) => a + Math.max(0, s.werte[i] || 0), 0), sicht.reduce((a, s) => a + Math.min(0, s.werte[i] || 0), 0)]);
  let mn = Math.min(...werte), mx = Math.max(...werte);
  if (art !== "linie" || nullLinie) { mn = Math.min(0, mn); mx = Math.max(0, mx); }
  const ax = achse(mn, mx);
  if (ax.lo < 0 && mn < 0 && -mn < ax.hi * 0.06) { ax.lo = mn * 1.6; ax.ticks = ax.ticks.filter(t => t >= 0); }   // kleiner Verlust: kein halbleeres Diagramm
  const y = v => T + ih - (v - ax.lo) / (ax.hi - ax.lo) * ih;
  const band = iw / n, x = i => L + (art === "linie" ? (n === 1 ? iw / 2 : i * iw / (n - 1)) : band * (i + 0.5));
  let s = `<svg viewBox="0 0 ${W} ${H}" height="${H}" role="img">`;
  for (const t of ax.ticks) s += `<line x1="${L}" x2="${W - R}" y1="${y(t)}" y2="${y(t)}" stroke="${t === 0 ? css("--t3") : css("--grid")}" stroke-width="1"/>
    <text x="${L - 6}" y="${y(t) + 4}" text-anchor="end">${kurz(t)}</text>`;
  const jede = Math.ceil(n / Math.max(2, Math.floor(iw / 62)));
  labels.forEach((lb, i) => { if (i % jede === 0 || (art === "linie" && i === n - 1 && n < 30)) s += `<text x="${x(i)}" y="${H - 6}" text-anchor="middle">${xfmt(lb)}</text>`; });
  if (art === "linie") {
    for (const se of sicht) {
      let d = "", an = false, erst = null, letzt = null;
      se.werte.forEach((v, i) => {
        if (v == null) { an = false; return; }
        d += !an ? "M" + x(i).toFixed(1) + " " + y(v).toFixed(1) : se.stufe ? "H" + x(i).toFixed(1) + "V" + y(v).toFixed(1) : "L" + x(i).toFixed(1) + " " + y(v).toFixed(1);
        an = true; if (erst == null) erst = i; letzt = i;
      });
      if (se.flaeche && erst != null) s += `<path d="${d}L${x(letzt).toFixed(1)} ${y(Math.max(ax.lo, 0)).toFixed(1)}L${x(erst).toFixed(1)} ${y(Math.max(ax.lo, 0)).toFixed(1)}Z" fill="${se.farbe}" fill-opacity="0.18" stroke="none"/>`;
      if (!se.nurPunkte) s += `<path d="${d}" fill="none" stroke="${se.farbe}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"${se.strich ? ` stroke-dasharray="${se.strich}"` : ""}/>`;
      if (se.nurPunkte) se.werte.forEach((v, i) => { if (v != null) s += `<circle cx="${x(i)}" cy="${y(v)}" r="5" fill="${css("--card")}" stroke="${se.farbe}" stroke-width="2.5"/>`; });
      else if (n <= 16) se.werte.forEach((v, i) => { if (v != null) s += `<circle cx="${x(i)}" cy="${y(v)}" r="3.5" fill="${se.farbe}" stroke="${css("--card")}" stroke-width="2"/>`; });
    }
  } else {
    const gap = 2, innen = Math.min(band * 0.72, 56);
    labels.forEach((_, i) => {
      if (art === "stapel") {
        let basis = 0, unten = 0;
        sicht.forEach((se, k) => {
          const roh = se.werte[i] || 0; if (!roh) return;
          if (roh < 0) {   // negative Werte (z.B. Verlust) unter die Nulllinie
            const y0 = y(unten), y1 = y(unten + roh);
            s += balkenPfad(x(i) - innen / 2, y0 + (unten < 0 ? gap : 0), innen, Math.max(0, y1 - y0 - (unten < 0 ? gap : 0)), -4, se.farbe);
            unten += roh; return;
          }
          const v = roh;
          const y1 = y(basis + v), y0 = y(basis), oben = k === sicht.length - 1 || sicht.slice(k + 1).every(z => !(z.werte[i] > 0));
          const h = Math.max(0, y0 - y1 - (basis > 0 ? gap : 0));
          s += balkenPfad(x(i) - innen / 2, y1, innen, h, oben ? 4 : 0, se.farbe);
          basis += v;
        });
      } else {
        const bw = (innen - gap * (sicht.length - 1)) / sicht.length;
        sicht.forEach((se, k) => {
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
    tip.innerHTML = `<b>${xfmt(labels[i])}</b>` + serien.filter(se => se.werte[i] != null || !se.nurPunkte).map(se => `<div class="r"><i class="sw" style="background:${se.nurTip ? "transparent" : se.farbe}"></i><span>${se.name}</span><span>${se.fmt ? se.fmt(se.werte[i]) : eur(se.werte[i])}</span></div>`).join("");
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
function tabWechseln(id) {
  const b = document.querySelector(`.tabs button[data-tab="${id}"]`);
  const ber = b.closest("#tabs-geschaeft") ? "geschaeft" : "privat";
  if (ber !== bereich) { letzterTab[ber] = id; bereichWechseln(ber); } else b.click();
}

function zeichneVermoegen(D) {
  if (vAnsicht === "depots") return zeichneDepots(D);
  if (vAnsicht === "konten") return zeichneKonten(D);
  const S1 = css("--s1"), S2 = css("--s2");
  const V = D.vermoegen, t = V.teile, DP = D.depots || [];
  const vk = t["Vorsorge kurzfristig"] || 0, vlg = t["Vorsorge langfristig"] || 0;
  const immoNetto = (t["Immobilien (Wert)"] || 0) + (t.Darlehen || 0) + (t.Mietkonten || 0);
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
      <div class="d">Wert ${kurz(t["Immobilien (Wert)"] || 0)} € − Darlehen ${kurz(-(t.Darlehen || 0))} €${t.Mietkonten ? ` + Mietkonten ${kurz(t.Mietkonten)} €` : ""}</div></button>
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
                   ["Vorsorge – langfristig", K.filter(k => k.art === "vorsorge" && k.vorsorge !== "kurzfristig"), "v-vorsorge-l"],
                   ["Treuhand – nicht im Vermögen (z.B. Mietkautionen)", K.filter(k => k.art === "treuhand"), "v-treuhand"]];
  let h = zurueck();
  for (const [titel, liste, id] of gruppen) {
    if (!liste.length) continue;
    liste.sort((a, b) => (b.saldo || 0) - (a.saldo || 0));
    const summe = liste.reduce((a, k) => a + (k.saldo || 0), 0);
    h += `<div class="card" id="${id}"><h2>${titel} <span style="float:right">${eur(summe)}</span></h2>` + tabelle([["Konto"], ["Zins", 1], ["Stand", 1], ["vom", 1]],
      liste.map(k => [esc(k.name) + (k.bewegungen.length || k.verlauf.length > 1 ? " ›" : "")
        + (k.nummer || k.institut ? `<div class="klein">${[k.institut, k.nummer && !k.name.replace(/\s/g, "").includes(k.nummer.replace(/\s/g, "")) ? k.nummer : null].filter(Boolean).map(esc).join(" · ")}</div>` : ""),
        k.zins != null ? pct(k.zins) + " p.a." : "", eur(k.saldo), datumDe(k.datum)])) + `</div>`;
  }
  const RT = D.renten || [];
  if (RT.length) h += card("Gesetzliche Rente – nur zur Information",
    tabelle([["Person"], ["Stand", 1], ["Anwartschaft heute", 1], ["Hochgerechnet", 1], ["ab", 1], ["Erwerbsminderung", 1]],
      RT.map(r => [esc(r.person || "–") + (r.versicherungsnummer ? `<div class="klein">Vers.-Nr. ${esc(r.versicherungsnummer)}</div>` : ""), datumDe(r.datum),
        r.rente_bisher != null ? eur(r.rente_bisher) + "<span class=\"kl\"> /Mon.</span>" : "–",
        r.rente_hochgerechnet != null ? `<b>${eur(r.rente_hochgerechnet)}</b><span class="kl"> /Mon.</span>` : "–",
        r.rentenbeginn ? datumDe(r.rentenbeginn) : "–",
        r.erwerbsminderung != null ? eur(r.erwerbsminderung) + "<span class=\"kl\"> /Mon.</span>" : "–"])),
    "Monatliche Renten laut Renteninformation der Deutschen Rentenversicherung · zählen nicht zum Vermögen und nicht zur Vorsorge-Summe · hochgerechnet = bei weiter durchschnittlichen Beiträgen, ohne Rentenanpassung"
    + RT.filter(r => r.rente_1pz).map(r => ` · ${esc((r.person || "").split(" ")[0])} mit 1 % / 2 % Anpassung: etwa ${eur(r.rente_1pz)} / ${eur(r.rente_2pz)}`).join(""));
  const det = K.filter(k => !["depot", "darlehen", "mietkonto"].includes(k.art) && (k.bewegungen.length || k.verlauf.length > 1));
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
    // Wertentwicklung aller Depots zusammen (aus dem Vermögensverlauf)
    const vv = (D.vermoegen.verlauf || []).filter(p => p.depot);
    if (vv.length > 1) h += card("Wertentwicklung aller Depots", platz("c-dpall", { labels: vv.map(p => p.d.slice(0, 7)), xfmt: monat, nullLinie: false,
        serien: [{ name: "Depot & Kapitalanlage", farbe: S1, werte: vv.map(p => p.depot) }] }),
      "Monatsende · vor dem ersten Depotauszug aus den Transaktionen geschätzt; Depots ohne Transaktionen (z.B. VB, FFB, Bison) zählen erst ab ihrem ersten bekannten Stand");
    h += card(`Alle Positionen (${alle.length}) nach Größe`, tabelle([["Position"], ["Wert", 1], ["Anteil", 1], ["Gewinn", 1], ["Depot"]],
      alle.map(p => [esc(p.name), eur(p.wert), pct((p.wert || 0) / gesamt * 100), eur(p.gewinn), `<span style="color:var(--t3)">${esc(p.depot)}</span>`])),
      "Gesamtrisiko: wo am meisten Geld steckt – unabhängig vom Depot");
    h += card("Depots im Überblick", tabelle([["Depot"], ["Wert", 1], ["Eingezahlt", 1], ["Gewinn", 1], ["Stand", 1]],
      L.map(d => [esc(d.name), eur(d.wert), eur(d.eingezahlt), eur(d.gewinn), datumDe(d.datum)])));
  } else {
    const J = dp.jahre || [];
    let hJahr = "";   // kommt nach dem Verlauf
    if (J.length) hJahr = card("Pro Jahr nach Buchungsdatum", legende([{ name: "Einzahlungen", farbe: S1 }, { name: "Käufe", farbe: S4 }, { name: "Erträge", farbe: S3 }, { name: "Auszahlungen", farbe: S2 }])
      + platz("c-dpj", { labels: J.map(j => String(j.jahr)), art: "balken", serien: [
          { name: "Einzahlungen", farbe: S1, werte: J.map(j => j.einzahlung) }, { name: "Käufe", farbe: S4, werte: J.map(j => j.kauf + j.wiederanlage) },
          { name: "Erträge", farbe: S3, werte: J.map(j => j.ertrag) }, { name: "Auszahlungen", farbe: S2, werte: J.map(j => j.auszahlung) }] })
      + tabelle([["Jahr"], ["Einzahlungen", 1], ["Auszahlungen", 1], ["Käufe", 1], ["Wiederanlage", 1], ["Verkäufe", 1], ["Erträge", 1], ["Gebühren", 1], ["Steuern", 1], ["Buchungen", 1]],
          J.slice().reverse().map(j => [j.jahr, eur(j.einzahlung), eur(j.auszahlung), eur(j.kauf), eur(j.wiederanlage), eur(j.verkauf), eur(j.ertrag), eur(j.gebuehr), eur(j.steuer), j.anzahl])));
    const EV = dp.einzahlungen_verlauf || [], WG = Object.fromEntries((dp.wert_geschaetzt || []).map(x => [x.m, x.w]));
    if (dp.grafik && dp.grafik.punkte.length > 2) {
      const G = dp.grafik.punkte;
      h += card("Eingezahlt und Depotwert im Verlauf", legende([{ name: "Eingezahlt (netto)", farbe: S4 }, { name: "Depotwert", farbe: S1 }])
        + platz("c-dpv", { labels: G.map(x => x.d), xfmt: d => monat(d.slice(0, 7)), nullLinie: true, serien: [
            { name: "Depotwert", farbe: S1, werte: G.map(x => x.w), flaeche: true },
            { name: "Eingezahlt (netto)", farbe: S4, werte: G.map(x => x.e), stufe: true }] }),
        `${datumDe(dp.grafik.von)} bis ${datumDe(dp.grafik.bis)} wöchentlich aus der Wertentwicklungsgrafik der Depotbank abgelesen (Genauigkeit etwa ±1 % der Skala) · letzter Punkt exakt laut Bericht`);
    } else if (EV.length > 1) {
      const wv = Object.fromEntries((dp.wert_verlauf || []).map(x => [x.d.slice(0, 7), x.w]));
      const EVm = Object.fromEntries(EV.map(x => [x.m, x.netto]));
      const mon = [...new Set([...EV.map(x => x.m), ...Object.keys(WG), ...Object.keys(wv)])].filter(m => m >= EV[0].m).sort();
      let letzt = null; const ein = mon.map(m => (letzt = EVm[m] ?? letzt));
      h += card("Eingezahlt und Depotwert im Verlauf", legende([{ name: "Eingezahlt (netto)", farbe: S4 }, { name: "Depotwert", farbe: S1 }])
        + platz("c-dpv", { labels: mon, xfmt: monat, nullLinie: false, serien: [
            { name: "Eingezahlt (netto)", farbe: S4, werte: ein },
            { name: "Depotwert", farbe: S1, werte: mon.map(m => wv[m] ?? WG[m] ?? null) }] }),
        dp.interpoliert ? `Kauf ${monat(dp.interpoliert[0])} und Depotauszug ${monat(dp.interpoliert[1])} sind belegt – dazwischen gleichmäßig verteilt (Schätzung, keine Tageskurse)`
          : "Depotwert = Bestand × letzter bekannter Kurs aus den Transaktionen, ab Kontoauszug echte Stände");
    }
    h += hJahr;
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

// ------------------------------------------------------------------ Geschäft
let gJahr = null, gPostenJahr = null, hkJahr = null, maWahl = "";
const tausch = (a, b) => a == null || b == null ? "" : delta(a, b);

function geschaeftKopf(D) {
  const G = D.geschaeft, gj = G.jahre.filter(j => j.quelle === "Abschluss"), KJ = G.konto_jahre || [];
  const jahre = [...gj.slice(-3).map(j => ({ jahr: j.jahr, art: "abschluss" })), ...KJ.map(k => ({ jahr: k.jahr, art: "konto" }))];
  if (!jahre.length) return leer("Noch keine Jahresabschlüsse.");
  if (gJahr == null || !jahre.some(j => j.jahr === gJahr)) gJahr = gj.length ? gj[gj.length - 1].jahr : jahre[jahre.length - 1].jahr;
  const auswahl = `<div class="seg wrap jahre" id="seg-gjahr">${jahre.map(j => `<button data-j="${j.jahr}" aria-pressed="${j.jahr === gJahr}">${j.jahr}${j.art === "konto" ? " · Konto" : ""}</button>`).join("")}</div>`;
  const a = gj.find(j => j.jahr === gJahr);
  let h = "";
  if (a) {
    const v = gj.find(j => j.jahr === gJahr - 1);
    h = `<div class="grid kpis">
      ${kpi("Umsatz " + a.jahr, eur(a.umsatz), v ? tausch(a.umsatz, v.umsatz) + " zu " + v.jahr : "")}
      ${kpi("Kosten " + a.jahr, eur(a.kosten), v ? tausch(a.kosten, v.kosten) + " zu " + v.jahr : "")}
      ${kpi("Gewinn " + a.jahr, eur(a.gewinn), v ? tausch(a.gewinn, v.gewinn) + " zu " + v.jahr : "")}
      ${kpi("Gewinnmarge " + a.jahr, pct(a.marge), "Gewinn ÷ Umsatz")}</div>
      <div class="hinweis">Alle vier Werte für dasselbe Jahr laut Jahresabschluss ${a.jahr}${a.sonstige_ertraege ? ` · Kosten und Gewinn beziehen sonstige betriebliche Erträge von ${eur(a.sonstige_ertraege)} mit ein` : ""}.</div>`;
  } else {
    const k = KJ.find(x => x.jahr === gJahr), ab = G.abweichung_konto_umsatz || [];
    const spanne = ab.length ? `In den Jahren mit Abschluss lagen diese Eingänge zwischen ${ab.map(x => (x > 0 ? "+" : "") + x + " %").sort((p, q) => parseInt(p) - parseInt(q)).filter((_, i, l) => i === 0 || i === l.length - 1).join(" und ")} neben dem Umsatz laut Abschluss.` : "";
    h = `<div class="grid kpis">
      ${kpi("Zahlungseingänge " + k.jahr + (k.vollstaendig ? "" : " (Ist)"), eur(k.ist), k.vollstaendig ? "Geschäftskonto, ganzes Jahr" : "Geschäftskonto bis " + datumDe(k.bis))}
      ${k.hochrechnung ? kpi("Hochrechnung " + k.jahr, eur(k.hochrechnung), "linear aufs Jahr gerechnet – Schätzung") : kpi("Umsatz " + k.jahr, "offen", "noch kein Jahresabschluss")}
      ${kpi("Kosten " + k.jahr, "offen", "aus dem Konto nicht belastbar")}
      ${kpi("Gewinn " + k.jahr, "offen", "kommt mit dem Jahresabschluss")}</div>
      <div class="warn">Zahlungseingänge von Auftraggebern (ohne eigene Überweisungen und Umbuchungen) sind <b>kein Umsatz</b>. ${spanne}
      Kosten und Gewinn lassen sich aus dem Konto noch nicht seriös ableiten, weil Privatentnahmen und betriebliche Ausgaben noch nicht sauber getrennt sind.${k.vollstaendig ? "" : ` Datenstand ${datumDe(k.bis)}.`}</div>`;
  }
  return auswahl + h;
}

function zeichneGeschaeft(D) {
  const S1 = css("--s1"), S2 = css("--s2"), S3 = css("--s3"), S4 = css("--s4");
  const G = D.geschaeft, gj = G.jahre;
  $("#g-kopf").innerHTML = geschaeftKopf(D);
  document.querySelectorAll("#seg-gjahr button").forEach(b => b.onclick = () => { gJahr = +b.dataset.j; $("#g-kopf").innerHTML = geschaeftKopf(D); zeichneGeschaeft(D); requestAnimationFrame(diagrammeZeichnen); });

  // --- Cashflow
  let h = "";
  if (G.cashflow.length) h += card("Geschäftskonto: Ein- und Auszahlungen", legende([{ name: "Eingänge", farbe: S1 }, { name: "Ausgänge", farbe: S2 }])
    + platz("c-gcf", { labels: G.cashflow.map(c => c.m), xfmt: monat, art: "balken", serien: [{ name: "Eingänge", farbe: S1, werte: G.cashflow.map(c => c.ein) }, { name: "Ausgänge", farbe: S2, werte: G.cashflow.map(c => c.aus) }] }),
    "letzte 24 Monate, ohne Umbuchungen · Eingänge sind nicht gleich Umsatz, Ausgänge enthalten auch Privatentnahmen");
  else h += card("", leer("Kontoumsätze des Geschäftskontos (CSV) in den Unterordner „Geschäft“ im Eingang legen."));
  const PE = gj.filter(j => j.privatentnahmen != null);
  h += `<div class="grid two">` + card("Geschäftliche Ausgaben nach Kategorie", (G.kosten_kategorien || []).length ? hbalken(G.kosten_kategorien.map(k => ({ label: k.k, wert: k.b, farbe: S2 }))) : leer("–"),
      "letzte 12 Monate · vorläufig: die Zuordnung der Buchungen wird noch verbessert")
    + card("Privatentnahmen laut Abschluss", PE.length ? tabelle([["Jahr"], ["Entnahmen", 1], ["Einlagen", 1]], PE.slice().reverse().map(j => [j.jahr, eur(j.privatentnahmen), eur(j.privateinlagen)])) : leer("–"),
      "Konto 1800 / 1890 im Kontennachweis") + `</div>`;
  $("#g-cashflow").innerHTML = h;

  // --- Steuern & Abschlüsse
  h = "";
  if (!gj.length) h = card("", leer("Noch keine Jahresabschlüsse. EÜR, GuV oder Jahresabschlüsse in den Eingang legen."));
  else {
    const lab = gj.map(j => String(j.jahr));
    h += card("Umsatz, Kosten und Gewinn pro Jahr", legende([{ name: "Kosten", farbe: S2 }, { name: "Gewinn", farbe: S1 }, ...(gj.some(j => j.gewinn < 0) ? [{ name: "Verlust", farbe: css("--t3") }] : [])])
      + platz("c-gj", { labels: lab, art: "stapel", hoehe: 260, serien: [
          { name: "Kosten", farbe: S2, werte: gj.map(j => j.gewinn < 0 ? (j.umsatz || 0) + (j.sonstige_ertraege || 0) : j.kosten) },
          { name: "Gewinn", farbe: S1, werte: gj.map(j => Math.max(0, j.gewinn || 0)) },
          { name: "Verlust", farbe: css("--t3"), werte: gj.map(j => j.gewinn < 0 ? j.gewinn : null) },
          { name: "Umsatz", nurTip: true, werte: gj.map(j => j.umsatz) },
          { name: "sonstige Erträge", nurTip: true, werte: gj.map(j => j.sonstige_ertraege || null) },
          { name: "Marge", nurTip: true, werte: gj.map(j => j.marge), fmt: v => pct(v) }] }),
      "Balkenhöhe = Umsatz (plus sonstige betriebliche Erträge), aufgeteilt in Kosten und den verbleibenden Gewinn · Verlust unter der Nulllinie");
    h += card("Jahresübersicht", tabelle([["Jahr"], ["Umsatz", 1], ["Kosten", 1], ["Gewinn", 1], ["Steuerl. Gewinn", 1], ["Marge", 1], ["Quelle"]],
      gj.slice().reverse().map(j => [j.jahr, eur(j.umsatz), eur(j.kosten), eur(j.gewinn), eur(j.steuerlicher_gewinn), pct(j.marge),
        (j.quelle === "BWA" ? `BWA (${j.monate} Mon.)` : j.quelle) + (j.abgleich ? ' <span class="ok" title="Umsatz + sonstige Erträge − Kosten = Gewinn">✓</span>' : "")])),
      "Steuerlicher Gewinn: nach außerbilanziellen Korrekturen (z.B. nicht abzugsfähige Ausgaben, Gewerbesteuer)");
    // Abschluss-Details
    const mitP = gj.filter(j => (j.posten || []).length);
    if (mitP.length) {
      if (gPostenJahr == null || !mitP.some(j => j.jahr === gPostenJahr)) gPostenJahr = mitP[mitP.length - 1].jahr;
      const a = mitP.find(j => j.jahr === gPostenJahr);
      h += card(`Abschluss im Detail <span class="seg" id="seg-posten">${mitP.map(j => `<button data-j="${j.jahr}" aria-pressed="${j.jahr === gPostenJahr}">${j.jahr}</button>`).join("")}</span>`,
        hbalken(a.posten.map(p => ({ label: p.gruppe, wert: p.betrag, farbe: S2, zusatz: pct(p.betrag / a.kosten * 100, 0) })))
        + `<div class="summe">Summe Kosten <b>${eur(a.kosten)}</b>${a.abgleich ? ' <span class="ok">✓ passt zum Abschluss</span>' : ' <span class="rot">weicht vom Abschluss ab</span>'}</div>`
        + `<details class="konten"><summary>Einzelkonten anzeigen</summary>${tabelle([["Konto"], ["Bezeichnung"], ["Posten"], ["Betrag", 1]],
            a.posten.flatMap(p => p.konten.map(k => [k.konto, esc(k.name), esc(p.gruppe), eur(k.betrag)])))}</details>`,
        `Kontennachweis aus „${esc(a.posten_datei || "")}“ · nur belegte Posten, nichts geschätzt`);
    }
    // betriebliche Steuern
    const BS = gj.filter(j => j.gewerbesteuer != null || j.ust_zahllast != null || j.einkuenfte_gewerbe != null);
    if (BS.length) {
      h += card("Betriebliche Steuern je Jahr", legende([{ name: "Gewerbesteuer", farbe: S2 }, { name: "Umsatzsteuer-Zahllast", farbe: S4 }, { name: "ESt-Anteil Gewerbe (rechnerisch)", farbe: S3 }])
        + platz("c-gst", { labels: BS.map(j => String(j.jahr)), art: "balken", serien: [{ name: "Gewerbesteuer", farbe: S2, werte: BS.map(j => j.gewerbesteuer) },
            { name: "Umsatzsteuer-Zahllast", farbe: S4, werte: BS.map(j => j.ust_zahllast) }, { name: "ESt-Anteil Gewerbe (rechnerisch)", farbe: S3, werte: BS.map(j => j.est_anteil_gewerbe ?? null) }] })
        + tabelle([["Jahr"], ["Gewinn lt. Abschluss", 1], ["Einkünfte Gewerbebetrieb", 1], ["Gewerbesteuer", 1], ["USt-Zahllast", 1], ["ESt-Anteil Gewerbe*", 1]],
          BS.slice().reverse().map(j => [j.jahr, eur(j.gewinn), eur(j.einkuenfte_gewerbe), eur(j.gewerbesteuer), eur(j.ust_zahllast), eur(j.est_anteil_gewerbe)])),
        "Einkünfte laut ESt-Bescheid · * abgeleitet: festgesetzte ESt × Anteil der Gewerbeeinkünfte an der Summe der Einkünfte – nicht aus dem Bescheid, wird nicht zu den privaten Steuern addiert");
    }
  }
  $("#g-abschluss").innerHTML = h;
  document.querySelectorAll("#seg-posten button").forEach(b => b.onclick = () => { gPostenJahr = +b.dataset.j; zeichneGeschaeft(D); requestAnimationFrame(diagrammeZeichnen); });

  // --- Statistiken (Einheiten laut Gesamtstatistik der Zentrale)
  const ST = G.statistik || [];
  const einh = (v, n = 0) => v == null ? "–" : v.toLocaleString("de-DE", { minimumFractionDigits: n, maximumFractionDigits: n }) + " E";
  const aktivN = j => j.mitarbeiter.filter(m => m.einheiten).length;
  const stJahre = [];
  if (ST.length) for (let y = ST[0].jahr; y <= ST[ST.length - 1].jahr; y++) stJahre.push(y);
  const stJ = y => ST.find(j => j.jahr === y);
  const fehlt = stJahre.filter(y => !stJ(y));
  let hs = "";
  if (!ST.length) hs = card("Statistiken", leer("Noch keine Gesamtstatistik. Die Jahresliste „Abgerechnetes Geschäft – Gesamtstatistik“ der Zentrale (PDF oder Excel) einfach in den Eingang legen."));
  else {
    const Z = ST[ST.length - 1], V = ST.length > 1 ? ST[ST.length - 2] : null;
    hs += `<div class="grid kpis">
      ${kpi(`Gruppenumsatz ${Z.jahr}`, einh(Z.gruppe), V ? `${Z.gruppe >= V.gruppe ? "+" : ""}${pct((Z.gruppe / V.gruppe - 1) * 100, 0)} zu ${V.jahr}` : "")}
      ${kpi("Anteil am Gesamtumsatz", pct(Z.gruppe / Z.gesamt * 100, 2), `Zentrale gesamt ${einh(Z.gesamt)}`)}
      ${kpi("Mitarbeiter", aktivN(Z) + (Z.mitarbeiter.length > aktivN(Z) ? ` <span class="kl">von ${Z.mitarbeiter.length}</span>` : ""), "mit Umsatz im Jahr")}
      ${kpi("Eigene Einheiten", einh(Z.eigen), Z.gruppe ? pct(Z.eigen / Z.gruppe * 100, 0) + " des Gruppenumsatzes" + (Z.stufe ? " · Stufe " + esc(Z.stufe) : "") : "")}
    </div>`;
    const RE = ST.filter(j => j.rang_einzeln), RG = ST.filter(j => j.rang_gruppe);
    const bestE = RE.reduce((m, j) => !m || j.rang_einzeln < m.rang_einzeln ? j : m, null), bestG = RG.reduce((m, j) => !m || j.rang_gruppe < m.rang_gruppe ? j : m, null);
    const platz_ = (r, n) => r ? `${r}. <span class="kl">von ${n}</span>` : "–";
    if (RE.length) hs += `<div class="grid kpis">
      ${kpi(`Platz Einzelberater ${Z.jahr}`, platz_(Z.rang_einzeln, Z.anzahl_berater), V && V.rang_einzeln ? `${V.jahr}: ${V.rang_einzeln}. Platz` : "nach eigenen Einheiten")}
      ${kpi(`Platz Gruppe ${Z.jahr}`, platz_(Z.rang_gruppe, Z.anzahl_gruppen), V && V.rang_gruppe ? `${V.jahr}: ${V.rang_gruppe}. Platz` : "nach E-Struktur")}
      ${kpi("Beste Platzierung einzeln", bestE ? bestE.rang_einzeln + ". Platz" : "–", bestE ? `${bestE.jahr} · ${einh(bestE.eigen)}` : "")}
      ${kpi("Beste Platzierung Gruppe", bestG ? bestG.rang_gruppe + ". Platz" : "–", bestG ? `${bestG.jahr} · ${einh(bestG.gruppe)}` : "")}
    </div>`;
    hs += card("Gruppenumsatz pro Jahr", legende([{ name: "Eigene Einheiten", farbe: S1 }, { name: "Einheiten der Mitarbeiter", farbe: S2 }])
      + platz("c-st-gruppe", { art: "stapel", labels: stJahre, serien: [
          { name: "Eigene Einheiten", farbe: S1, werte: stJahre.map(y => stJ(y) ? stJ(y).eigen : null) },
          { name: "Einheiten der Mitarbeiter", farbe: S2, werte: stJahre.map(y => stJ(y) ? Math.max(0, stJ(y).gruppe - stJ(y).eigen) : null) }] }),
      "Gruppenumsatz = E-Struktur laut Statistik der Zentrale" + (fehlt.length ? ` · ${fehlt.join(", ")}: keine Statistik vorhanden` : ""));
    hs += card("Anteil am Gesamtumsatz der Zentrale", legende([{ name: "mit Gruppe", farbe: S1 }, { name: "nur eigene Einheiten", farbe: S3 }])
      + platz("c-st-anteil", { labels: stJahre, xfmt: y => y, serien: [
          { name: "mit Gruppe", farbe: S1, werte: stJahre.map(y => stJ(y) ? stJ(y).gruppe / stJ(y).gesamt * 100 : null), fmt: v => pct(v, 2) },
          { name: "nur eigene Einheiten", farbe: S3, werte: stJahre.map(y => stJ(y) ? stJ(y).eigen / stJ(y).gesamt * 100 : null), fmt: v => pct(v, 2) }] }));
    const pl = (r, n) => r ? `${r}. <span class="kl">/ ${n}</span>` : "–";
    hs += card("Alle Jahre", tabelle([["Jahr"], ["Stufe"], ["Zentrale gesamt", 1], ["Eigene", 1], ["Platz einzeln", 1], ["Mitarbeiter-Einheiten", 1], ["Gruppe", 1], ["Platz Gruppe", 1], ["Anteil Gruppe", 1], ["Anteil eigen", 1], ["Mitarbeiter", 1]],
      stJahre.slice().reverse().map(y => { const j = stJ(y); return j
        ? [y, esc(j.stufe || "–"), einh(j.gesamt), einh(j.eigen), pl(j.rang_einzeln, j.anzahl_berater), einh(j.gruppe - j.eigen), `<b>${einh(j.gruppe)}</b>`, pl(j.rang_gruppe, j.anzahl_gruppen), pct(j.gruppe / j.gesamt * 100, 2), pct(j.eigen / j.gesamt * 100, 2), aktivN(j) + (j.mitarbeiter.length > aktivN(j) ? ` / ${j.mitarbeiter.length}` : "")]
        : [y, `<span class="rot">keine Statistik</span>`, "", "", "", "", "", "", "", "", ""]; })),
      "Einheiten (E) laut „Abgerechnetes Geschäft – Gesamtstatistik“ · Platz einzeln: nach eigenen Einheiten unter allen Beratern mit Umsatz · Platz Gruppe: nach E-Struktur unter allen Führungskräften mit Team, einschließlich deiner Vorgesetzten · Mitarbeiter: mit Umsatz / insgesamt · gespeichert werden nur deine Zeile, deine Gruppe, die Summe der Zentrale und deine Platzierung");
  }
  $("#g-statistik").innerHTML = hs;

  // --- Mitarbeiter
  const PA = gj.filter(j => (j.posten || []).some(p => p.gruppe === "Personal"));
  let hm = "";
  if (ST.length) {
    const alle = {};
    ST.forEach(j => j.mitarbeiter.forEach(m => {
      const a = alle[m.id] || (alle[m.id] = { id: m.id, name: m.name, stufe: m.stufe, ebene: m.ebene, j: {}, st: {}, erst: j.jahr, summe: 0 });
      a.j[j.jahr] = m.einheiten; a.st[j.jahr] = m.stufe; a.stufe = m.stufe || a.stufe; a.ebene = m.ebene ?? a.ebene; a.summe += m.einheiten || 0;
    }));
    const liste = Object.values(alle).sort((a, b) => b.summe - a.summe);
    const maJahre = stJahre.filter(y => stJ(y) && stJ(y).mitarbeiter.length);
    const teamE = y => stJ(y) ? stJ(y).mitarbeiter.reduce((x, m) => x + (m.einheiten || 0), 0) : null;
    const schnitt = y => stJ(y) && aktivN(stJ(y)) ? teamE(y) / aktivN(stJ(y)) : null;
    const e0 = v => v == null ? "" : v.toLocaleString("de-DE", { maximumFractionDigits: 0 });
    if (maWahl && !alle[maWahl]) maWahl = "";
    hm += `<div class="card filter"><label>Mitarbeiter <select id="ma-wahl"><option value="">Alle Mitarbeiter</option>${
      liste.slice().sort((a, b) => a.name.localeCompare(b.name, "de")).map(a => `<option value="${a.id}"${a.id === maWahl ? " selected" : ""}>${esc(a.name)} · ${e0(a.summe)} E</option>`).join("")}</select></label></div>`;
    if (maWahl) {
      // --- ein Mitarbeiter
      const a = alle[maWahl], J = maJahre.filter(y => y in a.j), letzt = J[J.length - 1], vor = J.length > 1 ? J[J.length - 2] : null;
      const best = J.reduce((m, y) => (a.j[y] || 0) > (a.j[m] || 0) ? y : m, J[0]);
      const rang = y => 1 + stJ(y).mitarbeiter.filter(m => (m.einheiten || 0) > (a.j[y] || 0)).length;
      hm += `<div class="grid kpis">
        ${kpi("Einheiten gesamt", einh(a.summe), `${J.length} ${J.length === 1 ? "Jahr" : "Jahre"} in deiner Struktur (${J[0]}${J.length > 1 ? "–" + letzt : ""})`)}
        ${kpi(`Einheiten ${letzt}`, einh(a.j[letzt]), vor != null && a.j[vor] ? `${a.j[letzt] >= a.j[vor] ? "+" : ""}${pct((a.j[letzt] / a.j[vor] - 1) * 100, 0)} zu ${vor}` : "")}
        ${kpi("Bestes Jahr", best + "", einh(a.j[best]))}
        ${kpi(`Anteil ${letzt}`, teamE(letzt) ? pct((a.j[letzt] || 0) / teamE(letzt) * 100, 0) : "–", `an den Einheiten aller Mitarbeiter · Platz ${rang(letzt)} von ${stJ(letzt).mitarbeiter.length}`)}
      </div>`;
      hm += card(`${esc(a.name)}: Einheiten pro Jahr`, legende([{ name: a.name, farbe: S1 }, { name: "Ø je Mitarbeiter mit Umsatz", farbe: S3 }])
        + platz("c-ma-einzeln", { art: "balken", labels: maJahre, serien: [
            { name: a.name, farbe: S1, werte: maJahre.map(y => y in a.j ? a.j[y] : null), fmt: v => einh(v) },
            { name: "Ø je Mitarbeiter mit Umsatz", farbe: S3, werte: maJahre.map(schnitt), fmt: v => einh(v) }] }),
        "Einzelumsatz laut Statistik der Zentrale · Jahre ohne Balken: nicht in deiner Struktur");
      hm += card("Entwicklung", tabelle([["Jahr"], ["Stufe"], ["Einheiten", 1], ["zum Vorjahr", 1], ["Anteil an den Mitarbeiter-Einheiten", 1], ["Platz", 1]],
        J.slice().reverse().map((y, k, R) => { const v = R[k + 1]; const d = v != null && a.j[v] ? (a.j[y] / a.j[v] - 1) * 100 : null;
          return [y, esc(a.st[y] || "–"), `<b>${einh(a.j[y])}</b>`, d == null ? "–" : `<span class="${d >= 0 ? "gruen" : "rot"}">${d >= 0 ? "+" : ""}${pct(d, 0)}</span>`,
                  teamE(y) ? pct((a.j[y] || 0) / teamE(y) * 100, 0) : "–", `${rang(y)} / ${stJ(y).mitarbeiter.length}`]; })),
        (a.ebene > 1 ? "nicht direkt unter dir, sondern unter einer deiner Führungskräfte · " : "") + "Platz = Rang nach Einheiten unter allen Mitarbeitern deiner Struktur im Jahr");
    } else {
      hm += card("Mitarbeiter pro Jahr", legende([{ name: "mit Umsatz", farbe: S1 }, { name: "ohne Umsatz", farbe: S3 }])
        + platz("c-ma-anzahl", { art: "stapel", labels: stJahre, serien: [
            { name: "mit Umsatz", farbe: S1, werte: stJahre.map(y => stJ(y) ? aktivN(stJ(y)) : null), fmt: v => v + " Mitarbeiter" },
            { name: "ohne Umsatz", farbe: S3, werte: stJahre.map(y => stJ(y) ? stJ(y).mitarbeiter.length - aktivN(stJ(y)) : null), fmt: v => v + " Mitarbeiter" }] }),
        "alle Vermittler unter dir in der Struktur laut Statistik der Zentrale" + (fehlt.length ? ` · ${fehlt.join(", ")}: keine Statistik` : ""));
      hm += card("Einheiten je Mitarbeiter und Jahr", tabelle([["Mitarbeiter"], ["Stufe"], ...maJahre.map(y => [String(y), 1]), ["Summe", 1]],
        liste.map(a => [`<a href="#" class="ma-link" data-ma="${a.id}">${a.ebene > 1 ? "<span class=\"kl\">↳ </span>" : ""}${esc(a.name)}</a>`, esc(a.stufe || "–"),
          ...maJahre.map(y => y in a.j ? (a.j[y] ? e0(a.j[y]) : "<span class=\"kl\">0</span>") : ""), `<b>${e0(a.summe)}</b>`])
          .concat([[`<b>Alle Mitarbeiter</b>`, "", ...maJahre.map(y => `<b>${e0(teamE(y))}</b>`), `<b>${e0(liste.reduce((x, a) => x + a.summe, 0))}</b>`]])),
        "Einheiten je Jahr (Einzelumsatz), sortiert nach Summe · Name antippen für die Entwicklung · leer = nicht in deiner Struktur · ↳ = unter einer deiner Führungskräfte · Stufe = zuletzt");
      hm += card("Einheiten deiner Mitarbeiter", tabelle([["Jahr"], ["Mitarbeiter", 1], ["Einheiten der Mitarbeiter", 1], ["Ø je Mitarbeiter mit Umsatz", 1], ["Anteil am Gruppenumsatz", 1]],
        ST.slice().reverse().map(j => { const t = j.gruppe - j.eigen, n = aktivN(j);
          return [j.jahr, n + (j.mitarbeiter.length > n ? ` / ${j.mitarbeiter.length}` : ""), einh(t), n ? einh(t / n) : "–", j.gruppe ? pct(t / j.gruppe * 100, 0) : "–"]; })),
        "Einheiten der Mitarbeiter = Gruppenumsatz minus eigene Einheiten. Was du daran verdient hast (Differenzprovision), steht nicht in der Statistik – dafür bräuchte ich die Abrechnungen bzw. den Einheitenwert je Stufe.");
    }
  }
  $("#g-mitarbeiter").innerHTML = hm + (!ST.length ? card("Mitarbeiter", leer("Sobald die Gesamtstatistik der Zentrale im Eingang liegt, erscheinen hier deine Mitarbeiter je Jahr.")) : "")
    + (PA.length ? card("Personalaufwand laut Abschluss", tabelle([["Jahr"], ["Personalaufwand", 1], ["Anteil an den Kosten", 1]],
        PA.slice().reverse().map(j => { const p = j.posten.find(x => x.gruppe === "Personal"); return [j.jahr, eur(p.betrag), pct(p.betrag / j.kosten * 100, 0)]; }))) : "");

  const maNeu = v => { maWahl = v; zeichneGeschaeft(D); requestAnimationFrame(diagrammeZeichnen); const f = $("#ma-wahl").closest(".card"), nav = document.querySelector("nav");
    window.scrollTo({ top: f.getBoundingClientRect().top + scrollY - (nav ? nav.getBoundingClientRect().bottom : 0) - 10 }); };
  if ($("#ma-wahl")) $("#ma-wahl").onchange = e => maNeu(e.target.value);
  document.querySelectorAll(".ma-link").forEach(l => l.onclick = e => { e.preventDefault(); maNeu(l.dataset.ma); });

  // --- Einnahmequellen
  const HJ = G.herkunft_jahre || {}, hjJahre = Object.keys(HJ).filter(k => HJ[k].length);
  const quellen = { "12": G.herkunft_12m || [], ...HJ };
  if (hkJahr == null || !quellen[hkJahr]) hkJahr = "12";
  const l = quellen[hkJahr] || [];
  $("#g-einnahmen").innerHTML = card(`Wichtige Auftraggeber <span class="seg" id="seg-hk">${["12", ...hjJahre].map(k => `<button data-k="${k}" aria-pressed="${k === hkJahr}">${k === "12" ? "12 Mon." : k}</button>`).join("")}</span>`,
      l.length ? hbalken(l.map(x => ({ label: x.name, wert: x.betrag, zusatz: pct(x.anteil, 0) }))) : leer("Keine Einnahmen im Zeitraum."),
      "Zahlungseingänge Geschäftskonto, ohne eigene Überweisungen und Umbuchungen – nicht gleich Umsatz")
    + (gj.some(j => (j.einnahmen_posten || []).length > 2) ? card("Einnahmen laut EÜR je Gesellschaft", tabelle([["Jahr"], ["Gesellschaft"], ["Einnahmen", 1]],
        gj.filter(j => (j.einnahmen_posten || []).length > 2).slice().reverse().flatMap(j => j.einnahmen_posten.map(e => [j.jahr, esc(e.name), eur(e.betrag)]))),
        "aus den Einnahme-Überschuss-Rechnungen (belegte Werte)") : "")
    + card("Auswertung nach Geschäftsfeld", leer("Folgt, sobald die Eingänge sauber Geschäftsfeldern (z.B. Versicherung, Investment, Finanzierung) zugeordnet sind."));
  document.querySelectorAll("#seg-hk button").forEach(b => b.onclick = () => { hkJahr = b.dataset.k; zeichneGeschaeft(D); });
}

// ------------------------------------------------------------------ Immobilien
let immoDetail = null;
const monJahr = d => d ? d.slice(5, 7) + "/" + d.slice(0, 4) : "–";
function wertHerkunft(o) {
  const b = o.wertbasis || {};
  if (!b.quelle) return "–";
  const ws = o.wertsteigerung == null ? "Wertansatz offen" : o.wertsteigerung === 0 ? "ohne Fortschreibung" : `fortgeschrieben mit ${pct(o.wertsteigerung * 100, 0)} p.a. (Schätzung)`;
  return `${esc(b.quelle)} vom ${datumDe(b.datum)}${b.geschaetzt ? (b.rueckwaerts ? " · zurückgerechnet (Schätzung)" : " · " + ws) : " · belegt"}`;
}
function kaufText(o) { return o.kaufdatum ? datumDe(o.kaufdatum) : o.kaufdatum_geschaetzt ? "ca. " + monJahr(o.kaufdatum_geschaetzt) + " (geschätzt)" : "–"; }

function zeichneImmobilien(D) {
  const S1 = css("--s1"), S2 = css("--s2"), S3 = css("--s3");
  const I = D.immobilien, O = I.objekte;
  if (!O.length) { $("#immobilien").innerHTML = card("", leer("Noch keine Immobilie erkannt. Kaufverträge, Darlehensverträge und Mietverträge in den Eingang legen.")); return; }
  if (immoDetail != null) {
    const o = O.find(x => x.id === immoDetail); if (o) return zeichneObjekt(D, o);
    const v = (I.verkauft || []).find(x => x.id === immoDetail); if (v) return zeichneVerkauft(D, v);
    immoDetail = null;
  }
  const sum = k => O.reduce((a, o) => a + (o[k] || 0), 0);
  const sumV = k => O.filter(o => o.nutzung !== "selbst").reduce((a, o) => a + (o[k] || 0), 0);
  let h = `<div class="grid kpis">
    ${kpi("Gesamtwert", eur(sum("wert")), O.length + " Objekte" + (O.some(o => o.anteil < 1) ? " · dein Anteil" : ""))}
    ${kpi("Restschuld", eur(sum("restschuld")), sum("wert") ? "Beleihung " + pct(sum("restschuld") / sum("wert") * 100, 0) : "")}
    ${kpi("Eigenkapital", eur(sum("ek")))}
    ${kpi("Kaltmiete / Monat", eur(sum("miete")), eur(sum("miete") * 12) + " im Jahr")}
    ${kpi("Cashflow / Monat", eur(sumV("cashflow")), "vermietete Objekte, nach Rate und Kosten, vor Steuern")}</div>`;
  h += I.hinweise.map(x => `<div class="warn">${esc(x)}</div>`).join("");
  // Laptop: gestapelte Balken · Smartphone: Zeilen mit horizontalem Balken
  h += `<div class="nur-gross">` + card("Wert je Objekt: Restschuld und Eigenkapital", legende([{ name: "Restschuld", farbe: S2 }, { name: "Eigenkapital", farbe: S1 }])
    + platz("c-obj", { labels: O.map(o => o.name), art: "stapel", hoehe: 250, xfmt: n => n.length > 14 ? n.slice(0, 13) + "…" : n,
      serien: [{ name: "Restschuld", farbe: S2, werte: O.map(o => o.restschuld) }, { name: "Eigenkapital", farbe: S1, werte: O.map(o => Math.max(0, o.ek)) }] }),
    "nach Gesamtwert sortiert · Werte mit deinem Anteil") + `</div>`;
  const mx = Math.max(...O.map(o => o.wert || 0), 1);
  h += `<div class="nur-klein">` + card("Objekte nach Wert", legende([{ name: "Restschuld", farbe: S2 }, { name: "Eigenkapital", farbe: S1 }])
    + O.map(o => `<button class="ozeile" data-id="${o.id}"><div class="oname">${esc(o.name)}<small>${esc((o.adresse || "").split(",").slice(1).join(",").trim())}</small></div>
      <div class="obalken"><div class="bahn" style="width:${(o.wert || 0) / mx * 100}%"><span style="width:${o.wert ? Math.min(100, o.restschuld / o.wert * 100) : 0}%;background:${S2}"></span><span style="flex:1;background:${o.warnung ? "var(--rot)" : S1}"></span></div>
      <div class="ozahl"><b>${eur(o.wert)}</b> · RS ${kurz(o.restschuld || 0)} € · EK ${kurz(o.ek || 0)} €</div></div></button>`).join(""),
    "nach Gesamtwert sortiert · antippen für Details") + `</div>`;
  const MK = I.mietkonten || [];
  if (MK.length) h += card(`Mietkonten <span style="float:right">${eur(MK.reduce((a, k) => a + (k.saldo || 0), 0))}</span>`,
    tabelle([["Konto"], ["Objekt"], ["Stand", 1], ["vom", 1]], MK.map(k => [esc(k.name), esc(k.objekt || "–"), eur(k.saldo), datumDe(k.datum)])),
    "zählen zu „Immobilien netto“ · Mietkautionen stehen unter Vermögen › Konten › Treuhand und zählen nicht mit");
  const opt = `<select id="obj-wahl"><option value="">Alle Objekte</option>${O.map(o => `<option value="${o.id}">${esc(o.name)}</option>`).join("")}</select>`;
  h += card(`Wert und Restschuld im Zeitverlauf <span style="float:right">${opt}</span>`, `<div id="tv-legende"></div><div class="chart" id="c-tv"></div><div id="tv-tab"></div>`, `<span id="tv-sub"></span>`);
  h += `<div class="grid objekte nur-gross">${O.map(o => `<button class="card obj kachel-obj" data-id="${o.id}"><h2>${esc(o.name)} <span class="pfeil">›</span></h2><div class="adr">${esc(o.adresse)}${o.anteil && o.anteil < 1 ? ` · Anteil ${pct(o.anteil * 100, 0)}${o.mit ? " (mit " + esc(o.mit) + ")" : ""}` : ""}${o.nutzung === "selbst" ? " · selbst genutzt" : ""}${o.status && /bau/i.test(o.status) ? " · im Bau" : ""}</div>
    ${o.hinweis ? `<div class="${o.warnung ? "rot" : "fehlt"}">${esc(o.hinweis)}</div>` : ""}<dl>
    <dt>Wert</dt><dd>${eur(o.wert)}</dd><dt>Restschuld</dt><dd>${eur(o.restschuld)}</dd><dt>Eigenkapital</dt><dd>${eur(o.ek)}</dd>
    <dt>Kaltmiete / Monat</dt><dd>${eur(o.miete)}</dd><dt>Rate / Monat</dt><dd>${eur(o.rate)}</dd><dt>Cashflow / Monat</dt><dd>${eur(o.cashflow)}</dd>
    <dt>Zinsbindung bis</dt><dd>${monJahr(o.zinsbindung)}</dd><dt>Kauf</dt><dd>${kaufText(o)}</dd></dl>
    <div class="wq">Wert: ${wertHerkunft(o)}</div></button>`).join("")}${(I.verkauft || []).map(v => verkaufKachel(v)).join("")}</div>`;
  if ((I.verkauft || []).length) h += `<div class="nur-klein">${card("Verkaufte Objekte", I.verkauft.map(v => verkaufKachel(v, true)).join(""))}</div>`;
  $("#immobilien").innerHTML = h;
  const tv = () => {
    const id = $("#obj-wahl").value, o = id ? O.find(x => x.id == id) : null;
    let opts, leg, sub = "", tab = "";
    if (!o) {
      const v = I.verlauf;
      opts = { labels: v.map(p => String(p.j)), serien: [{ name: "Wert", farbe: S1, werte: v.map(p => p.wert) }, { name: "Restschuld", farbe: S2, werte: v.map(p => p.rs) }] };
      leg = [{ name: "Wert", farbe: S1 }, { name: "Restschuld", farbe: S2 }];
      sub = "alle Objekte mit deinem Anteil · Wert je Objekt ab letztem belegten Stichtag fortgeschrieben (Schätzung) · Restschuld nach Tilgungsplan";
    } else {
      const v = o.verlauf_objekt, jetzt = new Date().getFullYear();
      opts = { labels: v.map(p => String(p.j)), serien: [
        { name: "Wert (Ist/fortgeschrieben)", farbe: S1, werte: v.map(p => p.j <= jetzt ? p.wert : null) },
        { name: "Wert (Prognose)", farbe: S1, strich: "5 4", werte: v.map(p => p.j >= jetzt ? p.wert : null) },
        { name: "belegter Wert", farbe: S3, nurPunkte: true, werte: v.map(p => p.belegt ? p.wert : null) },
        { name: "Restschuld", farbe: S2, werte: v.map(p => p.rs) }] };
      leg = [{ name: "Wert", farbe: S1 }, { name: "belegter Wert (Kaufpreis, Bewertung, Übersicht)", farbe: S3 }, { name: "Restschuld", farbe: S2 }];
      sub = `voller Objektwert · ${o.wertsteigerung == null ? "Wertansatz offen – keine Fortschreibung" : "Fortschreibung " + pct(o.wertsteigerung * 100, 0) + " p.a. als Planungsannahme"} · gestrichelt = Zukunft`;
      tab = `<details class="konten"><summary>Jahreswerte anzeigen</summary>${tabelle([["Jahr"], ["Wert", 1], ["Basis"], ["Restschuld", 1]],
        v.slice().reverse().map(p => [p.j, eur(p.wert), p.belegt ? `<span class="ok">belegt: ${esc(p.belegt)}</span>` : p.zukunft ? "Prognose" : "Schätzung", eur(p.rs) + (p.rs_ist ? " (Ist)" : "")]))}</details>`;
    }
    plaetze["c-tv"] = opts; $("#tv-legende").innerHTML = legende(leg); $("#tv-sub").textContent = sub; $("#tv-tab").innerHTML = tab;
    const el = $("#c-tv"); if (el.offsetParent !== null) diagramm(el, plaetze["c-tv"]);
  };
  $("#obj-wahl").onchange = tv; tv();
  document.querySelectorAll(".kachel-verkauft").forEach(b => b.onclick = () => { immoDetail = +b.dataset.id; zeichneImmobilien(D); window.scrollTo({ top: 0 }); });
  document.querySelectorAll(".kachel-obj, .ozeile").forEach(b => b.onclick = () => { immoDetail = +b.dataset.id; zeichneImmobilien(D); requestAnimationFrame(diagrammeZeichnen); window.scrollTo({ top: 0 }); });
}

function verkaufKachel(v, klein) {
  return `<button class="card obj kachel-verkauft${klein ? " klein" : ""}" data-id="${v.id}"><h2>${esc(v.name)} <span class="pfeil">›</span></h2>
    <div class="adr">${esc(v.adresse)} · verkauft</div><dl>
    <dt>Kauf</dt><dd>${v.kaufdatum ? datumDe(v.kaufdatum) : v.kaufjahr || "–"}</dd><dt>Kaufpreis</dt><dd>${eur(v.kaufpreis)}</dd><dt>Darlehen</dt><dd>${eur(v.darlehen)}</dd><dt>Verkaufspreis</dt><dd>${eur(v.verkaufspreis)}</dd>
    <dt>Gewinn (Verkauf − Kauf)</dt><dd class="gruen">${v.gewinn != null ? (v.gewinn > 0 ? "+" : "") + eur(v.gewinn) : "–"}</dd></dl>
    <div class="wq">mit Gewinn verkauft · zählt nicht mehr zum Vermögen</div></button>`;
}
function zeichneVerkauft(D, v) {
  let h = `<button class="link" id="i-zurueck" style="padding:0 0 4px;justify-self:start">‹ Zurück zur Immobilienübersicht</button>`;
  h += `<div class="card verkauft-kopf"><h2 style="font-size:19px;margin-bottom:2px">${esc(v.name)}</h2><div class="adr">${esc(v.adresse)} · verkauft${v.anteil < 1 ? " · Anteil " + pct(v.anteil * 100, 0) : ""}</div></div>`;
  h += `<div class="grid kpis">
    ${kpi("Kaufpreis", eur(v.kaufpreis), v.kaufdatum ? "Kauf " + datumDe(v.kaufdatum) : v.kaufjahr ? "Kauf " + v.kaufjahr : "")}
    ${kpi("Darlehen", eur(v.darlehen), v.eigenkapital_eingesetzt != null ? (v.eigenkapital_eingesetzt < 0 ? "über den Kaufpreis hinaus finanziert" : "Eigenkapital " + eur(v.eigenkapital_eingesetzt)) : "")}
    ${kpi("Verkaufspreis", eur(v.verkaufspreis))}
    ${kpi("Gewinn (Verkauf − Kauf)", `<span class="gruen">${v.gewinn != null ? (v.gewinn > 0 ? "+" : "") + eur(v.gewinn) : "–"}</span>`, "vor Nebenkosten, Tilgung und Steuern")}</div>`;
  h += card("Steuerliche Wirkung (Vermietung und Verpachtung)", (v.vuv || []).length
    ? tabelle([["Jahr"], ["Einkünfte / Verlust", 1]], v.vuv.slice().reverse().map(x => [x.jahr, x.betrag == null ? '<span class="rot">offen</span>' : eur(x.betrag)]))
      + `<div class="hinweis">Aktenzeichen: ${v.vuv_aktenzeichen.map(esc).join(", ")} · Werte laut Einkommensteuerbescheid</div>`
    : leer("Keine Einkünfte zugeordnet."));
  const ex = Object.entries(v.extra || {}).filter(([k]) => !/^nr$|^anteil$|^mit$|verkehrswert|^kaufpreis$|wertsteigerung|gewinn/i.test(k));
  if (ex.length) h += card("Objektangaben", `<dl class="dl zwei">${ex.map(([k, w]) => `<dt>${esc(k)}</dt><dd>${zahlFmt(k, w)}</dd>`).join("")}</dl>`, "aus der Immobilienübersicht (Excel)");
  $("#immobilien").innerHTML = h;
  $("#i-zurueck").onclick = () => { immoDetail = null; zeichneImmobilien(D); requestAnimationFrame(diagrammeZeichnen); window.scrollTo({ top: 0 }); };
}

function zahlFmt(k, v) {
  if (v == null || v === "") return "–";
  if (typeof v === "number") {
    if (/\(%\)|anteil|sollzins|tilgung$/i.test(k) && Math.abs(v) <= 1.5) return pct(v * 100, /zins|tilgung/i.test(k) ? 2 : 1);
    if (/baujahr|nr$|^nr|blatt|^mea$/i.test(k)) return String(v).replace(".", ",");
    if (/fl\.|fläche|grundstück/i.test(k)) return v.toLocaleString("de-DE", { maximumFractionDigits: 2 }) + " m²";
    return eur(v);
  }
  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) return datumDe(v);
  return esc(v);
}

function zeichneObjekt(D, o) {
  const S1 = css("--s1"), S2 = css("--s2"), S3 = css("--s3");
  const a = o.anteil || 1;
  let h = `<button class="link" id="i-zurueck" style="padding:0 0 4px;justify-self:start">‹ Zurück zur Immobilienübersicht</button>`;
  h += `<div class="card"><h2 style="font-size:19px;margin-bottom:2px">${esc(o.name)}</h2><div class="adr">${esc(o.adresse)} · ${esc(o.status || o.nutzung)}${a < 1 ? ` · Anteil ${pct(a * 100, 0)}${o.mit ? " (mit " + esc(o.mit) + ")" : ""}` : ""}</div>
    ${o.hinweis ? `<div class="${o.warnung ? "rot" : "fehlt"}" style="margin-top:6px">${esc(o.hinweis)}</div>` : ""}</div>`;
  if ((o.fotos || []).length) h += `<div class="fotos">${o.fotos.map(f => `<img src="${f}" alt="Foto ${esc(o.name)}" loading="lazy">`).join("")}</div>`;
  const anteilHinweis = a < 1 ? " (dein Anteil)" : "";
  h += `<div class="grid kpis">
    ${kpi("Wert" + anteilHinweis, eur(o.wert), wertHerkunft(o))}
    ${kpi("Restschuld" + anteilHinweis, eur(o.restschuld), o.beleihung != null ? "Beleihung " + pct(o.beleihung, 0) : "")}
    ${kpi("Eigenkapital" + anteilHinweis, eur(o.ek))}
    ${kpi("Kaltmiete / Monat", eur(o.miete), o.nutzung === "selbst" ? "selbst genutzt" : "")}
    ${kpi("Darlehensrate / Monat", eur(o.rate))}
    ${kpi("Kosten / Jahr", eur(o.kosten), (o.kosten_liste || []).length ? "aus den Unterlagen" : "noch keine Unterlagen")}
    ${kpi("Cashflow / Monat", eur(o.cashflow), "nach Rate und Kosten, vor Steuern")}
    ${kpi("Bruttomietrendite", pct(o.brutto), "Jahreskaltmiete ÷ Kaufpreis")}
    ${kpi("Kaufpreis", eur(o.kaufpreis), "Kauf " + kaufText(o))}
    ${kpi("Zinsbindung bis", monJahr(o.zinsbindung), o.rs_zinsbindung ? "Restschuld dann ca. " + eur(o.rs_zinsbindung) : "")}</div>`;
  // Wert-Historie
  h += card("Woher der Wert kommt", tabelle([["Stichtag"], ["Quelle"], ["Wert (voll)", 1], ["Datei"]],
      (o.belege || []).slice().reverse().map(b => [datumDe(b.datum), esc(b.quelle), eur(b.wert), esc(b.datei || "")]))
    + `<div class="hinweis">Aktueller Wert: ${wertHerkunft(o)}. ${o.wertsteigerung == null ? "Für dieses Objekt ist noch keine Wertentwicklung angesetzt." : `Die ${pct(o.wertsteigerung * 100, 0)} p.a. sind eine Planungsannahme, keine Marktwertentwicklung.`} Neue Bewertungen werden als weiterer belegter Wert ergänzt, frühere bleiben erhalten.</div>`);
  // Verlauf
  const v = o.verlauf_objekt || [], jetzt = new Date().getFullYear();
  if (v.length) h += card("Wert und Restschuld im Zeitverlauf", legende([{ name: "Wert", farbe: S1 }, { name: "belegter Wert", farbe: S3 }, { name: "Restschuld", farbe: S2 }])
    + platz("c-od", { labels: v.map(p => String(p.j)), serien: [
        { name: "Wert (Ist/fortgeschrieben)", farbe: S1, werte: v.map(p => p.j <= jetzt ? p.wert : null) },
        { name: "Wert (Prognose)", farbe: S1, strich: "5 4", werte: v.map(p => p.j >= jetzt ? p.wert : null) },
        { name: "belegter Wert", farbe: S3, nurPunkte: true, werte: v.map(p => p.belegt ? p.wert : null) },
        { name: "Restschuld", farbe: S2, werte: v.map(p => p.rs) }] }), "voller Objektwert, ohne Anteil · gestrichelt = Zukunft");
  // Darlehen
  (o.darlehen || []).forEach((d, i) => {
    const ex = d.extra || {};
    const zusatz = Object.entries(ex).filter(([k]) => !/darlehensnummer|^bank$|sollzins|^tilgung$|bindung|darlehenssumme|darlehensstand|annuität/i.test(k));
    h += card(`Darlehen ${esc(d.nummer)} · ${esc(d.bank || "")}`, `<div class="grid zwei-spalten"><dl class="dl">
        <dt>Ursprüngliche Summe</dt><dd>${eur(d.betrag)}</dd><dt>Sollzins</dt><dd>${d.zins != null ? pct(d.zins, 2) : "–"}</dd>
        <dt>Anfängliche Tilgung</dt><dd>${d.tilgung != null ? pct(d.tilgung, 2) : "–"}</dd><dt>Rate / Monat</dt><dd>${eur(d.rate)}</dd>
        <dt>Beginn</dt><dd>${d.beginn ? datumDe(d.beginn) : d.beginn_geschaetzt ? "ca. " + monJahr(d.beginn_geschaetzt) + " (geschätzt)" : "–"}</dd>
        <dt>Restschuld heute</dt><dd>${eur(d.restschuld)}</dd><dt>Letzter Ist-Stand</dt><dd>${d.restschuld_ist != null ? eur(d.restschuld_ist) + " am " + datumDe(d.restschuld_datum) : "–"}</dd>
        <dt>Zinsbindung bis</dt><dd>${d.zinsbindung ? datumDe(d.zinsbindung) : "–"}</dd><dt>Restschuld Zinsbindungsende</dt><dd>${eur(d.rs_zinsbindung)}</dd>
        ${zusatz.map(([k, w]) => `<dt>${esc(k)}</dt><dd>${zahlFmt(k, w)}</dd>`).join("")}</dl>
        <div>${(d.verlauf || []).length > 1 ? platz("c-dl" + i, { labels: d.verlauf.map(x => String(x.j)), serien: [{ name: "Restschuld", farbe: S2, werte: d.verlauf.map(x => x.rs) }], hoehe: 180 }) : ""}</div></div>`,
      "Tilgungsverlauf: ab letztem Ist-Stand mit Rate und Zins fortgerechnet");
  });
  // Mieten, Kosten
  if ((o.mieten || []).length) h += card("Miete", tabelle([["ab"], ["Kaltmiete", 1], ["Nebenkosten", 1], ["Mieter"], ["Quelle"]],
    o.mieten.slice().reverse().map(m => [datumDe(m.ab), eur(m.kalt), eur(m.nk), esc(m.mieter || ""), esc(m.quelle || "")])));
  h += card("Jährliche Kosten aus den Unterlagen", (o.kosten_liste || []).length ? tabelle([["Jahr"], ["Art"], ["Betrag (voll)", 1], ["Quelle"]],
    o.kosten_liste.slice().sort((p, q) => q.jahr - p.jahr).map(k => [k.jahr, esc(k.art), eur(k.betrag), esc(k.quelle || "")])) : leer("Noch keine Hausgeld-, Nebenkosten-, Grundsteuer- oder Versicherungsunterlagen."));
  // Stammdaten
  const ex = o.extra || {};
  const stamm = [["Adresse", esc(o.adresse)], ["Kaufdatum", kaufText(o)], ["Wohnfläche", o.flaeche ? o.flaeche.toLocaleString("de-DE") + " m²" : "–"],
    ...Object.entries(ex).filter(([k]) => !/^nr$|^anteil$|^mit$|wohnfl|verkehrswert$|^kaufpreis$/i.test(k)).map(([k, w]) => [esc(k), zahlFmt(k, w)])];
  h += card("Objektangaben", `<dl class="dl zwei">${stamm.map(([k, w]) => `<dt>${k}</dt><dd>${w}</dd>`).join("")}</dl>`, "aus Immobilienübersicht (Excel) und Verträgen");
  // Steuerliche Wirkung
  const VU = o.vuv || [];
  const gem = (o.vuv_gemeinsam || [])[0];
  h += card("Steuerliche Wirkung (Vermietung und Verpachtung)", (o.vuv_aktenzeichen || []).length
      ? tabelle([["Jahr"], [gem ? "Einkünfte / Verlust (gemeinsam)" : "Einkünfte / Verlust", 1]], VU.slice().reverse().map(x => [x.jahr, (x.offen && x.betrag == null ? '<span class="rot">offen</span>' : eur(x.betrag)) + (x.offen && x.betrag != null ? ' <span class="klein">(teilweise unleserlich)</span>' : "")]))
        + (gem ? `<div class="hinweis">Läuft über die Grundstücksgemeinschaft zusammen mit ${esc(gem.objekte.filter(z => !(o.adresse || "").startsWith(z)).join(", "))} – der Betrag gilt für beide Objekte zusammen (dein Anteil laut Bescheid). Die Aufteilung je Objekt folgt mit der Feststellungserklärung.</div>` : "")
        + `<div class="hinweis">Aktenzeichen: ${(o.vuv_aktenzeichen || []).map(esc).join(", ")} · Werte laut Einkommensteuerbescheid</div>`
      : leer("Aktenzeichen noch nicht zugeordnet – offen. Die Bescheide enthalten die Einkünfte je EW-Aktenzeichen (siehe Privat › Steuern); nach der Zuordnung erscheinen sie hier je Jahr."));
  $("#immobilien").innerHTML = h;
  $("#i-zurueck").onclick = () => { immoDetail = null; zeichneImmobilien(D); requestAnimationFrame(diagrammeZeichnen); window.scrollTo({ top: 0 }); };
}

// ------------------------------------------------------------------ Steuern (privat)
let stJahr = null;
const ESTFELDER = [
  ["Einkünfte aus Gewerbebetrieb", "e_gewerbe"], ["Einkünfte aus selbständiger Arbeit", "e_selbst"], ["Einkünfte aus nichtselbständiger Arbeit", "e_nsa"],
  ["Einkünfte aus Kapitalvermögen", "e_kap"], ["Einkünfte aus Vermietung und Verpachtung", "e_vuv"], ["Sonstige Einkünfte", "e_sonst"]];

function zeichneSteuern(D) {
  const S1 = css("--s1"), S3 = css("--s3"), S4 = css("--s4");
  const ST = D.steuern.jahre, STV = ST.filter(s => s.veranlagt);
  if (!STV.length) { $("#steuern").innerHTML = card("", leer("Noch keine Steuerbescheide. Einkommensteuerbescheide in den Eingang legen.")); return; }
  const erstes = STV[0].jahr, letztes = STV[STV.length - 1].jahr;
  const luecken = []; for (let j = erstes; j <= letztes; j++) if (!STV.some(s => s.jahr === j)) luecken.push(j);
  const voll = STV.filter(s => s.zve != null && s.einkommensteuer != null);
  const summe = k => voll.reduce((a, s) => a + (s[k] || 0), 0);
  const steuern = s => (s.einkommensteuer || 0) + (s.soli || 0) + (s.kirchensteuer || 0);
  const sZve = summe("zve"), sEst = summe("einkommensteuer"), sRest = voll.reduce((a, s) => a + s.zve - steuern(s), 0);
  const zr = `${voll[0].jahr}–${voll[voll.length - 1].jahr}, ${voll.length} Jahre${luecken.length ? " (ohne " + luecken.join(", ") + ")" : ""}`;
  let h = `<div class="grid kpis drei">
    ${kpi("Zu versteuerndes Einkommen, kumuliert", eur(sZve), "Ø " + eur(sZve / voll.length) + " pro Jahr")}
    ${kpi("Festgesetzte Einkommensteuer, kumuliert", eur(sEst), "Ø " + eur(sEst / voll.length) + " pro Jahr")}
    ${kpi("Nach festgesetzter Steuer verbleibend", eur(sRest), "Ø " + eur(sRest / voll.length) + " pro Jahr")}</div>
    <div class="hinweis">Zeitraum ${zr}. Verbleibend = zu versteuerndes Einkommen − Einkommensteuer − Solidaritätszuschlag − Kirchensteuer laut Bescheid.
    Das ist <b>nicht</b> das frei verfügbare Nettoeinkommen: Sozialabgaben, Versicherungsbeiträge und andere Abzüge sind nicht berücksichtigt.</div>`;
  if (luecken.length) h += `<div class="warn">Kein Bescheid für ${luecken.join(", ")} – Datenlücke, wird nicht geschätzt.</div>`;
  h += card("Einkommensteuer pro Jahr", legende([{ name: "Einkommensteuer", farbe: S1 }, { name: "Solidaritätszuschlag", farbe: S3 }, { name: "Kirchensteuer", farbe: S4 }])
    + platz("c-st", { labels: STV.map(s => String(s.jahr)), art: "stapel", serien: [{ name: "Einkommensteuer", farbe: S1, werte: STV.map(s => s.einkommensteuer) }, { name: "Solidaritätszuschlag", farbe: S3, werte: STV.map(s => s.soli) }, { name: "Kirchensteuer", farbe: S4, werte: STV.map(s => s.kirchensteuer) }] }));
  // Jahr im Detail
  if (stJahr == null || !STV.some(s => s.jahr === stJahr)) stJahr = letztes;
  const s = STV.find(x => x.jahr === stJahr);
  const fehlt = '<span class="fehlwert">fehlt</span>';
  const w = (v, abg) => v == null ? fehlt : eur(v) + (abg ? ' <span class="abg" title="rechnerisch: Summe der Einkünfte minus die übrigen Einkunftsarten (lesbare Ziffern passen)">≙</span>' : "");
  const ab = s.abgeleitet || [];
  const kap = s.e_kap != null && s.e_kap !== 0 ? w(s.e_kap) : s.kap_32d != null ? eur(s.kap_32d) + ' <span class="klein">(§ 32d EStG, Abgeltungsteuer)</span>' : w(s.e_kap);
  const zeilen = [
    ...ESTFELDER.map(([l, k]) => { const alt = s.se_zus == null ? { e_gewerbe: s.gewerbe, e_vuv: s.vuv }[k] : null; const v = s[k] ?? alt;
      return [l, k === "e_kap" ? kap : (v == null && ["e_selbst", "e_sonst"].includes(k) ? "–" : w(v, ab.includes(k.slice(2))))]; }),
    ["Summe der Einkünfte – Ehemann", w(s.se_mann)], ["Summe der Einkünfte – Ehefrau", s.se_frau == null && s.se_mann != null && s.se_zus === s.se_mann ? "–" : w(s.se_frau)],
    ["<b>Summe der Einkünfte – zusammen</b>", s.se_zus == null ? fehlt : "<b>" + eur(s.se_zus) + "</b>"],
    ["Gesamtbetrag der Einkünfte", w(s.gde)], ["Zu versteuerndes Einkommen", w(s.zve)],
    ["Festgesetzte Einkommensteuer", w(s.einkommensteuer)], ["Solidaritätszuschlag", w(s.soli)], ["Kirchensteuer", w(s.kirchensteuer)],
    ["Steuerbelastung gesamt (ESt + Soli + KiSt)", s.einkommensteuer == null ? fehlt : "<b>" + eur(steuern(s)) + "</b>"],
    ["Durchschnittssteuersatz auf das zvE", s.satz != null ? pct(s.satz) : "–"], ["Erstattung (+) / Nachzahlung (−)", s.abrechnung != null ? eur(s.abrechnung) : "–"]];
  h += card(`Bescheid ${s.jahr} <span class="seg" id="seg-st">${STV.slice().reverse().map(x => `<button data-j="${x.jahr}" aria-pressed="${x.jahr === stJahr}">${x.jahr}</button>`).join("")}</span>`,
    `<table class="detail">${zeilen.map(([l, v]) => `<tr><td>${l}</td><td class="n">${v}</td></tr>`).join("")}</table>`,
    `Quelle: ${s.quelle === "Bescheid" ? "Einkommensteuerbescheid" : s.quelle === "Erklärung" ? "Steuerberechnung/Erklärung (kein Bescheid hochgeladen)" : s.quelle} · Werte wie im Bescheid, nichts geschätzt · „fehlt“ = im Dokument nicht (lesbar) enthalten`);
  // alle Jahre
  h += card("Alle Jahre", tabelle([["Jahr"], ["Quelle"], ["Gewerbe", 1], ["Nichtselbst.", 1], ["Kapital", 1], ["V+V", 1], ["Summe Eink.", 1], ["GdE", 1], ["zvE", 1], ["ESt", 1], ["Soli", 1], ["KiSt", 1], ["Gesamt", 1]],
    STV.slice().reverse().map(x => [x.jahr, x.quelle, eur(x.e_gewerbe ?? (x.se_zus == null ? x.gewerbe : null)), eur(x.e_nsa), eur(x.e_kap || x.kap_32d), eur(x.e_vuv ?? (x.se_zus == null ? x.vuv : null)), eur(x.se_zus), eur(x.gde), eur(x.zve),
      eur(x.einkommensteuer), eur(x.soli), eur(x.kirchensteuer), eur(x.gesamt)])), "– = im Bescheid nicht enthalten oder nicht lesbar");
  // V+V je Aktenzeichen
  const AZ = [...new Set(STV.flatMap(x => Object.keys(x.vuv_az || {})))];
  if (AZ.length) {
    const J = STV.filter(x => Object.keys(x.vuv_az || {}).length);
    const zuo = D.steuern.aktenzeichen || {};
    h += card("Vermietung und Verpachtung je Aktenzeichen", tabelle([["EW-Aktenzeichen"], ["Objekt"], ...J.map(x => [String(x.jahr), 1])],
      AZ.map(az => [esc(az), zuo[az] ? esc(zuo[az]) : '<span class="rot">offen</span>', ...J.map(x => az in (x.vuv_az || {}) ? (x.vuv_az[az] == null ? '<span class="fehlwert">unleserlich</span>' : eur(x.vuv_az[az])) : "")])),
      "aus den Bescheiden (Summe Ehemann + Ehefrau) · die Zuordnung zu den Immobilien folgt, sobald du mir die Aktenzeichen nennst");
  }
  const KAP = ST.filter(x => x.kap_ertrag != null);
  if (KAP.length) h += card("Kapitalerträge aus Fondsdepots", tabelle([["Jahr"], ["Steuerpflichtiger Ertrag", 1], ["Abgeltungsteuer inkl. Soli/KiSt", 1]],
    KAP.slice().reverse().map(x => [x.jahr, eur(x.kap_ertrag), eur(x.abgeltung)])), "bereits von der Bank einbehalten (u.a. Vorabpauschale)");
  $("#steuern").innerHTML = h;
  document.querySelectorAll("#seg-st button").forEach(b => b.onclick = () => { stJahr = +b.dataset.j; zeichneSteuern(D); requestAnimationFrame(diagrammeZeichnen); });
}

function zeichnen() {
  for (const k in plaetze) delete plaetze[k];
  const D = DATEN, S1 = css("--s1"), S2 = css("--s2"), S3 = css("--s3"), S4 = css("--s4");
  $("#stand").textContent = "Stand " + datumDe(D.stand.slice(0, 10)) + ", " + D.stand.slice(11, 16) + " Uhr";

  // ---------- Vermögen (Übersicht oder Unterseite Konten / Depots)
  zeichneVermoegen(D);

  // ---------- Geschäft, Immobilien, Steuern
  zeichneGeschaeft(D);
  zeichneImmobilien(D);
  zeichneSteuern(D);

  // ---------- Fuß
  const P = D.dokumente.pruefen;
  $("#fuss").innerHTML = `${D.dokumente.ok} Dokumente verarbeitet.` + (P.length ? `<details><summary>${P.length} Datei(en) im Ordner „Prüfen“</summary>${tabelle([["Datei"], ["Grund"]], P.map(p => [esc(p.datei), esc(p.grund)]))}</details>` : "");
  requestAnimationFrame(diagrammeZeichnen);
}
document.querySelectorAll(".tabs button").forEach(b => b.addEventListener("click", () => requestAnimationFrame(diagrammeZeichnen)));
let rz; window.addEventListener("resize", () => { clearTimeout(rz); rz = setTimeout(() => DATEN && diagrammeZeichnen(), 150); });
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => DATEN && zeichnen());

start();
