"use strict";
const $ = (id) => document.getElementById(id);
const post = (m) => window.webkit.messageHandlers.nm.postMessage(m);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const S = { mac: null, pkg: "", kit: false, previewed: false, installed: false, driverUpdate: false };
// The systems the move starts from, and every system this app runs on (those and the one it moves to).
const OS_FROM = [15, 26], OS_OK = [15, 26, 27];
// The sentences of the verdict card are in the page (index.html), not here.
const V = $("verdict").dataset;

function row(k, v) { return `<tr><th>${esc(k)}</th><td>${v}</td></tr>`; }
function step(n, state) { const li = $("s" + n); li.classList.toggle("done", state === "done"); li.classList.toggle("now", state === "now"); }

function render(m) {
  S.mac = m;
  $("ver").textContent = m.version;
  const card = m.gpus.find((g) => g.supported) || m.gpus.find((g) => g.vendor === "10DE");
  const on = m.kexts >= 4 && m.metal.some((n) => /NVIDIA|GeForce|RTX/i.test(n));
  $("mac").innerHTML =
    row("macOS", esc(m.macos) + (OS_OK.includes(m.major) ? "" : ' <span class="bad">(not a macOS Liberator runs on)</span>')) +
    row("Processor", m.arch === "x86_64" && !m.translated ? "x86_64" : '<span class="bad">Apple silicon - this driver is for Intel Macs and PCs</span>') +
    row("Graphics", m.gpus.length ? m.gpus.map((g) => esc(g.name) + (g.supported ? (g.tested ? ' <span class="good">listed device, model tested</span>' : ' <span class="warn">listed by NVIDIA, model not tested yet</span>') : g.vendor === "10DE" ? ' <span class="bad">not supported (needs RTX 20 series or newer)</span>' : "")).join("<br>") : "none found") +
    row("OpenCore", m.opencore ? esc(m.opencore) : m.nativeMacPro ? 'not needed: Mac Pro (2019) on Apple\'s firmware <span class="warn">(experimental, needs SIP off)</span>' : '<span class="warn">not detected</span>') +
    row("Installed driver package", m.installedDriverVersion ? esc(m.installedDriverVersion) : "No version record") +
    row("NullMoth driver", on ? '<span class="good">running</span> (' + esc(m.metal.join(", ")) + ")" : m.kexts >= 4 ? '<span class="warn">loaded, no NVIDIA Metal device yet</span>' : m.files ? '<span class="warn">installed, not running yet</span>' : "not installed");

  let why = "";
  if (m.arch !== "x86_64" || m.translated) why = "This Mac has Apple silicon. Its own graphics are already Apple's.";
  else if (!OS_OK.includes(m.major)) why = esc(V.otherOs) + esc(m.macos) + ".";
  else if (!card && (m.gpuHiding || []).some((a) => a !== "-wegnoigpu")) why = `No NVIDIA card is visible because this Mac starts with ${esc(m.gpuHiding.filter((a) => a !== "-wegnoigpu").join(" "))}, which hides discrete GPUs. Remove it from boot-args in OpenCore's config.plist, restart, and open Liberator again.`;
  else if (!card && (m.hiddenNvidia || []).length) why = `The NVIDIA card (${esc(m.hiddenNvidia.join(", "))}) is on the bus but switched off for macOS, usually by a disable-gpu property in OpenCore's DeviceProperties. Remove it, restart, and open Liberator again.`;
  else if (!card && /^MacBook/.test(m.hwModel || "")) why = "No NVIDIA card was found. On a laptop the card is often switched off before macOS starts: by the BIOS graphics mode (choose Hybrid/MSHybrid or Discrete, not iGPU only) or by a dGPU-off SSDT in OpenCore's ACPI folder. Fix that, restart, and open Liberator again.";
  else if (!card || !card.supported) why = "No supported NVIDIA card was found. The driver needs a GeForce RTX 20 series or newer.";
  else if (!m.opencore && !m.nativeMacPro) why = "This Mac does not report OpenCore. The driver's settings live in OpenCore's config, so Liberator will not work without it.";

  // Keep the checked package available when the driver is already running.
  const pk = m.packages.find((p) => p.ok === "yes"); if (pk) S.pkg = pk.path;
  // Golden Gate: the card exists only when this build carries a kit pin; its steps run only from the starting systems
  $("ggcard").hidden = !m.goldenGate;
  S.ggReady = !!m.goldenGate && OS_FROM.includes(m.major) && !why;
  S.ggKit = m.ggKit || "none";
  const kept = $("ggkept"), mb = Number(m.ggKeptMB) || 0;
  kept.textContent = mb > 0 ? kept.dataset.kept.replace("{n}", (mb / 1000).toFixed(1)) : kept.dataset.none;
  ggButtons(false);
  // The words for the kit are in the page (index.html), not here.
  $("ggkit").textContent = S.ggKit === "other" ? $("ggkit").dataset.update : $("ggkit").dataset.get + (m.ggKitMB ? " (downloads " + m.ggKitMB + " MB)" : "");
  $("ggkitr").textContent = S.ggKit === "current" ? $("ggkitr").dataset.current : S.ggKit === "other" ? $("ggkitr").dataset.other : "";
  if (m.goldenGate && !S.ggReady && !$("ggt").textContent) $("ggt").textContent = OS_FROM.includes(m.major) ? $("ggt").dataset.need : $("ggt").dataset.from;
  $("steps").hidden = true;
  if (why) { $("verdict").innerHTML = `<p class="bad">Liberator can't be used here.</p><p>${why}</p>`; return; }
  // On a starting system the driver there belongs to the other app; this one only makes the move.
  if (OS_FROM.includes(m.major)) {
    $("verdict").innerHTML = `<p class="good">${esc(V.ready)}</p>` + (on ? "" : `<p>${esc(V.driverHere)}</p>`);
    return;
  }
  if (on) { $("verdict").innerHTML = `<p class="good">${esc(V.on27)}</p>`; return; }
  $("verdict").innerHTML = `<p class="warn">${esc(V.off27)}</p>`;
  // The driver steps: on the new system the install is the kit's own, so there is no package to get. The app refuses
  // the install with its reason when the kit is not on this Mac.
  S.kit = !!m.goldenGate;
  $("steps").hidden = !S.kit;
  $("s1t").textContent = $("s1t").dataset.kit; step(1, "done");
  $("dry").disabled = !S.kit;
  goState();
  if (!S.previewed) step(2, "now");
}

// A greyed-out button with no reason sent users to Discord (10-13: "Install Driver is greyed out, what do I do"): the
// button says which step comes first.
function goState() {
  $("go").disabled = !S.kit || !S.previewed;
  $("go").textContent = !S.previewed ? "Install the driver (press Show me the changes first)" : "Install the driver";
  $("go").title = !S.previewed ? "Step 2 lists every change first; then this button turns on." : "";
}

function logLine(l) {
  const kind = l.split(" ")[0], rest = esc(l.slice(kind.length + 1));
  const cls = { STEP: "s", CHANGE: "c", OK: "k", STOP: "x", RESULT: "s" }[kind];
  const txt = kind === "STEP" ? "== " + rest : kind === "CHANGE" ? "will change: " + rest : kind === "OK" ? "ok  " + rest : kind === "STOP" ? "STOPPED: " + rest : kind === "NOTE" ? "    " + rest : kind === "RESULT" ? (rest === "ok" ? "done." : "stopped - nothing after the red line was changed.") : esc(l);
  $("log").insertAdjacentHTML("beforeend", (cls ? `<span class="${cls}">${txt}</span>` : txt) + "\n");
  $("log").scrollTop = $("log").scrollHeight;
  const m = l.match(/^NOTE candidate (\S+)/);
  if (m) { $("efirow").hidden = false; if (![...$("efi").options].some((o) => o.value === m[1])) $("efi").insertAdjacentHTML("beforeend", `<option value="${esc(m[1])}">${esc(m[1])}</option>`); }
}

const NM = {
  on({ event, data }) {
    if (event === "scan") render(data);
    if (event === "lines") data.forEach(logLine);
    if (event === "ggprogress") $("ggt").textContent = data;
    if (event === "ggbar") ggBar(data.pct, data.text);
    if (event === "dl") {
      if (data.state === "progress") {
        // Update driver shows its own line; without this the progress went to step 1 and the update looked stuck.
        const mb = (n) => (n / 1048576).toFixed(1);
        const t = data.total > 0 ? `${Math.floor((100 * data.done) / data.total)}% (${mb(data.done)} of ${mb(data.total)} MB)` : `${mb(data.done)} MB`;
        if (S.driverUpdate) $("updr").textContent = `Downloading the newest driver: ${t}`;
      }
      if (data.state === "start") ["updchk", "upddrv"].forEach((b) => ($(b).disabled = true));
      if (data.state === "error" || data.state === "done") ["updchk", "upddrv"].forEach((b) => ($(b).disabled = false));
      if (data.state === "error") {
        if (S.driverUpdate) { S.driverUpdate = false; $("updr").innerHTML = `<span class="bad">${esc(data.why)}</span>`; }
      }
      if (data.state === "done") {
        if (S.driverUpdate) { $("updr").textContent = "Download checked. Installing the driver..."; $("upddrv").disabled = true; }
        post({ act: "scan" });
      }
    }
    if (event === "upd") {
      if (data.state === "error") { $("updr").innerHTML = `<span class="bad">${esc(data.why)}</span>`; $("upddrv").hidden = true; }
      if (data.state === "checked") {
        const have = data.installed ? `installed ${esc(data.installed)}, ` : "";
        const kind = data.prerelease ? "early release " : "";
        $("updr").innerHTML = !data.installed
          ? `Liberator could not tell which driver version is installed. The newest ${kind}is ${esc(data.latest)}; updating to it is safe either way.`
          : data.newer ? `${have}newest ${kind}${esc(data.latest)} - ready to update.` : `${have}you have the newest driver (${esc(data.latest)}).`;
        // A driver release is for the starting systems, and those belong to the other app: it is named, never installed here.
        const offer = data.newer && !(S.mac && OS_FROM.includes(S.mac.major));
        $("upddrv").hidden = !offer;
        $("upddrv").disabled = !offer;
        if (data.app) $("updr").innerHTML += data.appNewer ? ` App ${esc(data.appHave)} -> ${esc(data.app)} is ready.` : ` The app (${esc(data.appHave)}) is up to date.`;
        $("updapp").hidden = !data.appNewer;
        $("updapp").disabled = !data.appNewer;
      }
    }
    if (event === "appupd") {
      if (data.state === "error") { $("updapp").disabled = false; $("updr").innerHTML = `<span class="bad">${esc(data.why)}</span>`; }
      if (data.state === "start") $("updr").textContent = `Downloading Liberator ${data.version}...`;
      if (data.state === "restarting") $("updr").textContent = `Liberator ${data.version} checked - restarting into it...`;
    }
    if (event === "run") {
      const busy = data.state === "start";
      ["dry", "go", "rm", "updchk", "upddrv"].forEach((b) => ($(b).disabled = busy));
      ggButtons(busy);
      if (busy) { $("logwrap").hidden = false; $("log").textContent = ""; return; }
      if (data.why) { $("logwrap").hidden = false; logLine(data.why); }
      if (data.state === "cancelled") {
        if (S.driverUpdate) { S.driverUpdate = false; $("updr").textContent = "Driver update cancelled."; }
        logLine("NOTE cancelled - nothing was changed"); post({ act: "scan" }); return;
      }
      if (S.driverUpdate && data.mode === "install") {
        S.driverUpdate = false;
        if (data.ok) {
          $("updr").textContent = "Driver installed. Restart to load it.";
          $("upddrv").hidden = true;
          $("upddrv").disabled = true;
        } else { $("updr").textContent = "Driver update stopped. Review the setup log below."; }
      }
      if (data.mode === "dry" && data.ok) { S.previewed = true; step(2, "done"); step(3, "now"); }
      if (data.mode === "install" && data.ok) { S.installed = true; step(3, "done"); step(4, "now"); $("rs").disabled = false; }
      if (data.mode === "goldengate" && data.ok && !$("ggbar").hidden) ggBar(100, "100%  Done");
      if (data.mode === "goldengate") $("ggt").textContent = data.ok ? GG_DONE[S.ggStep] || (S.ggStep === "kit" ? $("ggkit").dataset.done : S.ggStep === "all" ? $("ggprep").dataset.done : "Done.") : "Stopped. Review the setup log above.";
      post({ act: "scan" });
    }
  },
};
window.NM = NM;

const efi = () => ($("efirow").hidden ? "auto" : $("efi").value);
$("efi").onchange = () => {
  S.previewed = false;
  goState();
  step(2, "now"); step(3, "waiting");
};
// The Golden Gate bar: one percentage for the whole run and one line under it, both worked out by the app from the
// progress lines of the scripts. It never moves back; a new run starts it again.
function ggBar(pct, text) {
  if (pct === null) { S.ggPct = 0; $("ggbar").hidden = $("ggbart").hidden = true; return; }
  S.ggPct = Math.max(S.ggPct || 0, Math.min(100, pct | 0));
  $("ggbar").hidden = $("ggbart").hidden = false;
  $("ggbarf").style.width = S.ggPct + "%";
  $("ggbar").setAttribute("aria-valuenow", S.ggPct);
  $("ggbart").textContent = text;
}
const GG_BUTTONS = ["ggprep", "ggkc", "gginst", "ggfin", "ggact", "ggcancel", "ggrm", "ggclr", "ggdoff", "ggdon"];
const GG_NO_KIT = ["ggcancel", "ggrm", "ggclr"];
// The forward steps need this build's kit on the Mac; getting the kit, cancelling, removing and clearing do not.
function ggButtons(busy) {
  GG_BUTTONS.forEach((b) => ($(b).disabled = busy || !S.ggReady || (b === "ggprep" ? S.ggKit === "none" : !GG_NO_KIT.includes(b) && S.ggKit !== "current")));
  ["ggkit", "ggkitf"].forEach((b) => ($(b).disabled = busy || !S.ggReady || S.ggKit === "none" || S.ggKit === "current"));
}
const GG_DONE = {
  prepare: "Staged. This Mac still starts the same way. Next: make the kernel collections.",
  installer: "The new system is on its own volumes. Next: set it up, before its first start.",
  collections: "The kernel collections are made. Next: install the new system.",
  finish: "The new system is set up. Next: start from the new startup files.",
  activate: "This Mac now starts from the new startup files; the old ones are kept. Restart and choose the new volume.",
  cancel: "Golden Gate cancelled: the startup files are as they were.",
  remove: "The new system is removed and the startup files are as they were. The downloads are kept.",
  "clear-downloads": "The downloads are cleared.",
  "drivers-off": "The unproven drivers are off for the new system. Restart and choose it; then press Send logs so the driver can be fixed.",
  "drivers-on": "The drivers are on for the new system again.",
};
// "Prepare for Golden Gate" is the whole move in one run (step "all"); the single steps keep their handlers but the
// page does not show their buttons.
[["ggprep", "all"], ["gginst", "installer"], ["ggkc", "collections"], ["ggfin", "finish"], ["ggact", "activate"], ["ggcancel", "cancel"], ["ggrm", "remove"], ["ggclr", "clear-downloads"], ["ggdoff", "drivers-off"], ["ggdon", "drivers-on"]].forEach(([id, step]) => {
  $(id).onclick = () => { S.ggStep = step; $("ggt").textContent = ""; ggBar(null); post({ act: "goldengate", step, efi: efi(), bringAccount: !$("ggnew").checked, sizeGB: Number($("ggsize").value) || 0 }); };
});
[["ggkit", false], ["ggkitf", true]].forEach(([id, file]) => {
  $(id).onclick = () => { S.ggStep = "kit"; $("ggt").textContent = ""; ggBar(null); post({ act: "goldengate", step: "kit", file, efi: efi() }); };
});
$("updchk").onclick = () => { $("updr").textContent = "Checking..."; post({ act: "checkUpdate" }); };
$("updapp").onclick = () => { $("updapp").disabled = true; post({ act: "updateApp" }); };
$("upddrv").onclick = () => { S.driverUpdate = true; $("upddrv").disabled = true; $("updr").textContent = "Downloading the newest driver..."; post({ act: "updateDriver", efi: efi() }); };
$("ocg").onclick = (e) => { e.preventDefault(); post({ act: "open", url: "https://dortania.github.io/OpenCore-Install-Guide/" }); };
$("dry").onclick = () => post({ act: "run", mode: "dry", pkg: "", efi: efi() });
$("go").onclick = () => post({ act: "run", mode: "install", pkg: "", efi: efi() });
$("rm").onclick = () => { if (confirm("Remove the NullMoth driver and put your OpenCore config back the way it was?")) post({ act: "run", mode: "remove", pkg: "", efi: efi() }); };
$("rs").onclick = () => post({ act: "restart" });
$("vbon").onclick = () => post({ act: "verbose", on: true, efi: efi() });
$("vboff").onclick = () => post({ act: "verbose", on: false, efi: efi() });
$("blon").onclick = () => post({ act: "backlight", on: true, efi: efi() });
$("bloff").onclick = () => post({ act: "backlight", on: false, efi: efi() });
$("hdon").onclick = () => post({ act: "hidpi", on: true, efi: efi() });
$("hdoff").onclick = () => post({ act: "hidpi", on: false, efi: efi() });
$("earlyon").onclick = () => post({ act: "early", on: true });
$("earlyoff").onclick = () => post({ act: "early", on: false });
post({ act: "early" });
$("efichk").onclick = () => { $("efichk").disabled = true; $("efichkr").textContent = "Reading the EFI..."; $("efiout").textContent = ""; post({ act: "checkEfi" }); };
$("tccg").onclick = () => { $("tccr").textContent = "Pick the app..."; post({ act: "tccGrant" }); };
$("gpumap").onclick = () => { $("gpumap").disabled = true; $("gpumapr").textContent = "Starting..."; post({ act: "gpumap" }); };
$("priv").onclick = (e) => { e.preventDefault(); post({ act: "privacy" }); };
$("logs").onclick = (e) => { e.preventDefault(); post({ act: "logs" }); };
$("src").onclick = (e) => { e.preventDefault(); post({ act: "open", url: "https://github.com/nullmoth/nvidia-macos-driver" }); };
post({ act: "scan" });

document.querySelectorAll(".tab").forEach((b) => (b.onclick = () => {
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("on", x === b));
  ["drv", "efi", "tools", "usb", "crash"].forEach((t) => ($("t-" + t).hidden = t !== b.dataset.t));
  $("ttl").textContent = "Liberator — " + b.dataset.title;
  if (b.dataset.t !== "usb") post({ act: "usbStop" });
}));
// Light or dark: the switch in the title bar, remembered on this Mac; until it is used, the system's setting decides.
// Storage can be unavailable; the switch still works for the session.
function setTheme(light) {
  $("desk").classList.toggle("light", light);
  try { localStorage.setItem("theme", light ? "light" : "dark"); } catch (e) { /* the switch still works this session */ }
}
(() => {
  let saved = null;
  try { saved = localStorage.getItem("theme"); } catch (e) { /* no stored choice */ }
  const prefersLight = typeof window.matchMedia === "function" && window.matchMedia("(prefers-color-scheme: light)").matches;
  $("desk").classList.toggle("light", saved ? saved === "light" : prefersLight);
})();
$("theme").onclick = () => setTheme(!$("desk").classList.contains("light"));
$("efimount").onclick = () => { $("efimount").disabled = true; $("efimountr").textContent = "Finding the EFI..."; post({ act: "mountEfi" }); };
const CONN = [[0, "USB 2 Type-A"], [3, "USB 3 Type-A"], [9, "USB-C (flips)"], [10, "USB-C (one way)"], [255, "Inside the case"]];
function usbConnectorDefault(port) {
  if (port.connectorKnown === true && CONN.some(([value]) => value === port.connector)) return port.connector;
  return port.usb3 ? 3 : 0;
}
const U = { ctrls: [], seen: {}, pick: {}, off: new Set(), last: "" };
function usbRender() {
  let h = "";
  for (const c of U.ctrls) {
    const name = c.key || c.controller, seen = new Set(U.seen[name] || []);
    const n = Object.keys(U.pick[name] || {}).length;
    h += `<table class="pc ports" border="1" cellspacing="2" cellpadding="3"><caption>Controller ${esc(c.controller)} (${esc(c.vendor)}:${esc(c.device)}) &mdash; <span class="${n > 15 ? "bad" : ""}">${n} of 15 picked</span></caption><tr><th>Use</th><th>Port</th><th>Seen</th><th>Plug</th><th>Device now</th></tr>`;
    for (const p of c.ports) {
      const on = seen.has(p.name), pk = (U.pick[name] || {})[p.name];
      const def = usbConnectorDefault(p);
      h += `<tr><td><input type="checkbox" data-c="${esc(name)}" data-p="${esc(p.name)}" ${pk !== undefined ? "checked" : ""}></td><td>${esc(p.name)}${p.usb3 ? " (USB 3)" : ""}</td><td class="${on ? "on" : "off"}">${on ? "yes" : "no"}</td>` +
        `<td><select data-c="${esc(name)}" data-p="${esc(p.name)}">${CONN.map(([v, t]) => `<option value="${v}" ${(pk ?? def) === v ? "selected" : ""}>${t}</option>`).join("")}</select></td><td>${esc((p.devices || []).join(", "))}</td></tr>`;
    }
    h += "</table>";
  }
  $("ports").innerHTML = h;
  $("ports").querySelectorAll("input").forEach((i) => (i.onchange = () => {
    const c = i.dataset.c, p = i.dataset.p; U.pick[c] = U.pick[c] || {};
    if (i.checked) { U.off.delete(c + "/" + p); U.pick[c][p] = +i.closest("tr").querySelector("select").value; } else { U.off.add(c + "/" + p); delete U.pick[c][p]; }
    usbRender();
  }));
  $("ports").querySelectorAll("select").forEach((s) => (s.onchange = () => {
    const c = s.dataset.c, p = s.dataset.p; U.pick[c] = U.pick[c] || {};
    // choosing a plug type is choosing the port: an unticked row is ticked with that type rather than reset on redraw
    U.off.delete(c + "/" + p); U.pick[c][p] = +s.value; usbRender();
  }));
}
$("uw").onclick = () => { U.pick = {}; U.off = new Set(); U.last = ""; post({ act: "usbStart" }); $("uw").textContent = "Watching..."; $("uw").disabled = true; };
$("uwr").onclick = () => { $("uerr").textContent = ""; post({ act: "usbStop" }); post({ act: "usbWrite", sel: U.pick, efi: efi() }); };
$("mk").onclick = () => post({ act: "crashReport" });
$("cf").onclick = () => post({ act: "open", url: "https://buymeacoffee.com/nullmoth" });
// every project Liberator is built on or downloads, with its author and licence
$("cr").onclick = () => post({ act: "open", url: "https://github.com/nullmoth/1401/blob/main/NOTICE.md" });
$("sl").onclick = () => { $("sl").disabled = true; $("slr").textContent = "Collecting and sending..."; post({ act: "sendLogs" }); };
$("fl").onclick = () => { $("sl").disabled = true; $("fl").disabled = true; $("slr").textContent = "Recording the display for 20 seconds, then sending..."; post({ act: "sendLogs", sample: "flicker" }); };
$("od").onclick = () => post({ act: "optionalDiagnostics" });
$("dr").onclick = () => post({ act: "importDiagnosticReceipt" });
$("up").onclick = () => post({ act: "open", url: "https://nullmothsystems.com/#send" });
const prevOn = NM.on;
NM.on = (m) => {
  if (m.event === "diagnosticsStatus") { $("odr").textContent = m.data.text; return; }
  if (m.event === "diagnosticReceipt") { $("drr").textContent = m.data.text; return; }
  if (m.event === "usb") {
    // The scan reports every second. Rebuilding the table each time closed a plug-type list while it was open and put
    // back the default plug on rows not yet ticked, so choices looked like they changed by themselves (10-23 chat).
    // The table is rebuilt only when the controllers, their devices or the ports seen have changed.
    const snap = JSON.stringify([m.data.controllers, m.data.seen]);
    if (snap === U.last) return;
    U.last = snap;
    U.ctrls = m.data.controllers; U.seen = m.data.seen;
    for (const c of U.ctrls) {   // a port that has been seen is ticked automatically, with its default plug type
      const key = c.key || c.controller;
      U.pick[key] = U.pick[key] || {};
      for (const p of c.ports) if ((U.seen[key] || []).includes(p.name) && !(p.name in U.pick[key]) && !U.off.has(key + "/" + p.name)) U.pick[key][p.name] = usbConnectorDefault(p);
    }
    usbRender(); return;
  }
  if (m.event === "usbErr") { $("uerr").textContent = m.data; return; }
  if (m.event === "early") {
    $("earlyr").textContent = m.data.on ? "On: new drivers reach this Mac first, before they are offered to everyone." : "Off: this Mac gets releases once they have held up for everyone who went first.";
    $("earlyon").hidden = m.data.on; $("earlyoff").hidden = !m.data.on;
    return;
  }
  if (m.event === "logsStatus") { $("slr").textContent = m.data.text; return; }
  if (m.event === "efiCheck") {
    const d = m.data;
    $("efichk").disabled = false;
    $("efiout").textContent = "";
    if (d.cancelled) { $("efichkr").textContent = ""; return; }
    if (!d.ok) { $("efichkr").innerHTML = `<span class="warn">${esc(d.why || "The check did not finish.")}</span>`; return; }
    const n = d.issues.length;
    $("efin").hidden = !n; $("efin").textContent = n;
    $("efichkr").innerHTML = n ? `<span class="warn">${n} thing${n === 1 ? "" : "s"} to change in ${esc(d.partition)}</span>`
                               : `<span class="good">No problems found in ${esc(d.partition)}</span>`;
    // built from text nodes: the titles and steps come from the rule file, never parsed as HTML
    for (const i of d.issues) {
      const box = document.createElement("details"), sum = document.createElement("summary"), b = document.createElement("b");
      b.textContent = i.title; sum.appendChild(b); box.appendChild(sum);
      const what = document.createElement("p"); what.textContent = i.what + (i.restart ? " Takes effect at the next restart." : ""); box.appendChild(what);
      // the exact values in this Mac's config and what each must become
      if ((i.now || []).length) {
        const now = document.createElement("div"); now.className = "now";
        const lab = document.createElement("b"); lab.textContent = "On this Mac: "; now.appendChild(lab);
        now.appendChild(document.createTextNode(i.now.join(" ")));
        box.appendChild(now);
      }
      const ol = document.createElement("ol");
      for (const s of i.steps) { const li = document.createElement("li"); li.textContent = s; ol.appendChild(li); }
      box.appendChild(ol);
      $("efiout").appendChild(box);
    }
    if (n) {
      const note = document.createElement("p");
      note.textContent = $("efiout").dataset.keep;
      $("efiout").appendChild(note);
    }
    return;
  }
  if (m.event === "efiMount") {
    $("efimount").disabled = false;
    $("efimountr").innerHTML = m.data.cancelled ? "" : m.data.ok ? `<span class="good">Mounted ${esc(m.data.partition)} at ${esc(m.data.where)}</span>`
                                                              : `<span class="warn">${esc(m.data.why || "The EFI could not be mounted.")}</span>`;
    return;
  }
  if (m.event === "tccStatus") { $("tccr").innerHTML = m.data.text ? `<span class="${m.data.ok ? "good" : "warn"}">${esc(m.data.text)}</span>` : ""; return; }
  if (m.event === "gpumapStatus") { $("gpumapr").textContent = m.data.text; if (m.data.done) $("gpumap").disabled = false; return; }
  if (m.event === "logsDone") {
    const d = m.data;
    $("sl").disabled = false; $("fl").disabled = false;
    $("slr").innerHTML = d.ok ? `<span class="good">Sent. Report ID ${esc(d.ids.join(", "))}</span> - quote it when you ask for help.` + (d.errors.length ? `<br><span class="warn">Not sent: ${esc(d.errors.join("; "))}</span>` : "")
                              : `<span class="warn">${esc(d.why || ("Nothing was sent: " + (d.errors || []).join("; ")))}</span>`;
    if (d.localPath) $("slr").innerHTML += "<br>Report files are saved locally. Open Logs to find them or retry Send logs.";
    return;
  }
  if (m.event === "crashDone") { $("crr").innerHTML = m.data.ok ? `<span class="good">Saved to your Desktop:</span> ${esc(m.data.path.split("/").pop())}` : `<span class="warn">${esc(m.data.why)}</span>`; return; }
  if (m.event === "scan" && m.data.crashes) $("crr").textContent = m.data.crashes.length ? `${m.data.crashes.length} crash file(s) on this Mac name the driver.` : "No crash that names the driver is on this Mac.";
  prevOn(m);
};
window.NM = NM;
