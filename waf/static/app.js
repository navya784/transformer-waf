const $ = id => document.getElementById(id);
const EX = [
  {n:"Normal search", m:"GET", p:"/search", q:"q=running shoes", b:"", e:"benign"},
  {n:"Name O'Brien", m:"GET", p:"/search", q:"q=O'Brien", b:"", e:"benign"},
  {n:"Text 'select a seat'", m:"GET", p:"/search", q:"q=select a seat", b:"", e:"benign"},
  {n:"Login (normal)", m:"POST", p:"/login", q:"", b:'{"username":"alice","password":"hunter22"}', e:"benign"},
  {n:"SQLi: OR 1=1", m:"GET", p:"/search", q:"q=' OR 1=1 --", b:"", e:"sqli"},
  {n:"SQLi: UNION SELECT", m:"GET", p:"/products", q:"id=1 UNION SELECT username,password FROM users", b:"", e:"sqli"},
  {n:"SQLi: URL-encoded", m:"GET", p:"/search", q:"q=%27%20OR%201%3D1%20--", b:"", e:"sqli"},
  {n:"SQLi: login body", m:"POST", p:"/login", q:"", b:'{"username":"admin\'--","password":"x"}', e:"sqli"},
  {n:"XSS: script tag", m:"GET", p:"/search", q:"q=<script>alert(1)</script>", b:"", e:"xss"},
  {n:"XSS: img onerror", m:"GET", p:"/search", q:"q=<img src=x onerror=alert(2)>", b:"", e:"xss"},
  {n:"XSS: comment body", m:"POST", p:"/comment", q:"", b:"comment=<svg onload=alert(1)>", e:"xss"}
];
const history = [];

async function inspect(r){
  const res = await fetch("/inspect", {method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({method:r.m, path:r.p, query:r.q, body:r.b})});
  if(!res.ok) throw new Error("API error " + res.status);
  return res.json();
}
const current = () => ({m:$("method").value, p:$("path").value, q:$("query").value, b:$("body").value});
const summary = r => r.m + " " + r.p + (r.q ? "?" + r.q : "") + (r.b ? "  [" + r.b + "]" : "");
const el = (tag, cls, text) => { const x = document.createElement(tag); if(cls) x.className = cls; if(text !== undefined) x.textContent = text; return x; };

function render(r, d){
  const box = $("result"); box.className = ""; box.replaceChildren();
  const v = el("div", "verdict " + (d.blocked ? "bad" : "ok"), d.blocked ? "BLOCKED" : "ALLOWED");
  v.append(el("small", "", "class: " + d.label + "  |  malicious score " + (d.malicious_score*100).toFixed(1) + "%"));
  box.append(v);
  for (const [name, p] of Object.entries(d.probs)){
    const bar = el("div", "bar"), t = el("div", "t");
    t.append(el("span", "", name), el("span", "", (p*100).toFixed(2) + "%"));
    const b = el("div", "b"), i = el("i"); i.style.width = (p*100) + "%"; b.append(i);
    bar.append(t, b); box.append(bar);
  }
  box.append(el("label", "", "Text the model saw (after decoding/normalising)"), el("pre", "", d.model_input));
}

function addHistory(r, d){
  history.unshift({r, d, t:new Date().toLocaleTimeString()});
  if(history.length > 25) history.pop();
  const tb = $("hist"); tb.replaceChildren();
  for(const h of history){
    const tr = el("tr");
    tr.append(el("td", "", h.t), el("td", "mono", summary(h.r)));
    const td = el("td"); td.append(el("span", "pill " + (h.d.blocked ? "bad" : "ok"), h.d.blocked ? "blocked" : "allowed")); tr.append(td);
    tr.append(el("td", "", h.d.label), el("td", "", (h.d.malicious_score*100).toFixed(1) + "%"));
    tb.append(tr);
  }
}

async function run(r){
  try { const d = await inspect(r); render(r, d); addHistory(r, d); return d; }
  catch(e){ $("result").className = "muted"; $("result").textContent = "Error: " + e.message; }
}

$("go").onclick = () => run(current());
for(const ex of EX){
  const b = el("button", "ghost", ex.n);
  b.onclick = () => { $("method").value = ex.m; $("path").value = ex.p; $("query").value = ex.q; $("body").value = ex.b; run(ex); };
  $("chips").append(b);
}

$("suite").onclick = async () => {
  const out = $("suiteOut"); out.className = ""; out.replaceChildren(el("span", "muted", "Running..."));
  const table = el("table"), head = el("tr");
  ["Example","Expected","Got","Result"].forEach(h => head.append(el("th", "", h))); table.append(head);
  let pass = 0;
  for(const ex of EX){
    try {
      const d = await inspect(ex), ok = d.label === ex.e; if(ok) pass++;
      const tr = el("tr"); tr.append(el("td","",ex.n), el("td","",ex.e), el("td","",d.label));
      const td = el("td"); td.append(el("span", "pill " + (ok ? "ok" : "bad"), ok ? "pass" : "FAIL")); tr.append(td); table.append(tr);
    } catch(e){ const tr = el("tr"); tr.append(el("td","",ex.n), el("td","",ex.e), el("td","","error"), el("td","","FAIL")); table.append(tr); }
  }
  out.replaceChildren(el("p", "", pass + " / " + EX.length + " passed"), table);
};