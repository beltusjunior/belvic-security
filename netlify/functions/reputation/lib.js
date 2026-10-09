// Reputation checks that need a server: malware/phishing blocklists, email blocklists,
// and the website's security headers and software version.
// Shared by the website (Netlify function) and the prospect engine (src/reputation.js is a copy).
const UA = "BelvicSecurityCheck/1.0 (+https://belvic-security.netlify.app)";

// WordPress releases older than this are treated as out of date. Bump it about once a year.
const MIN_WP = [6, 5];

// Public mail blocklists that answer lookups from shared resolvers.
const MAIL_BLOCKLISTS = [
  { zone: "bl.spamcop.net", name: "SpamCop" },
  { zone: "psbl.surriel.com", name: "PSBL" }
];

function timeout(p, ms){
  return Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), ms))]);
}

async function doh(url, name, type){
  const r = await timeout(fetch(`${url}?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: "application/dns-json" } }), 4000);
  if(!r.ok) throw new Error("dns");
  const j = await r.json();
  return { status: j.Status, answers: (j.Answer || []).map(a => a.data) };
}
const google = (n, t) => doh("https://dns.google/resolve", n, t);
const cfSecurity = (n, t) => doh("https://security.cloudflare-dns.com/dns-query", n, t);

// Cloudflare's security resolver (1.1.1.2) answers 0.0.0.0 for domains its threat feeds
// flag as malware or phishing. Compared against a normal lookup.
async function malware(host){
  const normal = await google(host, "A").catch(() => null);
  if(!normal || normal.status !== 0 || !normal.answers.length) return { checked: false };
  const cf = await cfSecurity(host, "A").catch(() => null);
  if(!cf) return { checked: false };
  return { checked: true, host, flaggedBy: cf.answers.includes("0.0.0.0") ? ["Cloudflare threat intelligence"] : [] };
}

const isIPv4 = s => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);
async function mailBlocklists(domain){
  const mx = await google(domain, "MX").catch(() => null);
  const hosts = (mx ? mx.answers : []).map(a => a.split(" ").pop().replace(/\.$/, "")).filter(Boolean).slice(0, 4);
  if(!hosts.length) return { checked: false };
  const ips = [...new Set((await Promise.all(hosts.map(h => google(h, "A").then(r => r.answers.filter(isIPv4)).catch(() => [])))).flat())].slice(0, 6);
  if(!ips.length) return { checked: false };
  const listed = [];
  await Promise.all(ips.flatMap(ip => MAIL_BLOCKLISTS.map(async bl => {
    const name = ip.split(".").reverse().join(".") + "." + bl.zone;
    const r = await google(name, "A").catch(() => null);
    if(r && r.status === 0 && r.answers.some(a => /^127\./.test(a))) listed.push({ ip, list: bl.name });
  })));
  return { checked: true, ips, listed };
}

async function website(domain){
  for(const host of [domain, "www." + domain]){
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), 4000);
    try{
      const r = await fetch("https://" + host, { redirect: "follow", signal: ctl.signal, headers: { "user-agent": UA } });
      const h = k => r.headers.get(k) || "";
      const csp = h("content-security-policy");
      const body = (await r.text()).slice(0, 300000);
      const gen = (body.match(/<meta[^>]+name=["']generator["'][^>]*content=["']([^"']+)["']/i) || body.match(/<meta[^>]+content=["']([^"']+)["'][^>]*name=["']generator["']/i) || [])[1] || "";
      const wp = (gen.match(/WordPress\s+(\d+)\.(\d+)/i) || []).slice(1).map(Number);
      return {
        reached: true, url: r.url,
        headers: {
          hsts: !!h("strict-transport-security"),
          clickjacking: !!h("x-frame-options") || /frame-ancestors/i.test(csp),
          sniffing: /nosniff/i.test(h("x-content-type-options")),
          csp: !!csp
        },
        generator: gen.slice(0, 80),
        wordpress: wp.length === 2 ? { version: wp.join("."), outdated: wp[0] < MIN_WP[0] || (wp[0] === MIN_WP[0] && wp[1] < MIN_WP[1]) } : null
      };
    }catch{ /* try the next host */ }
    finally{ clearTimeout(t); }
  }
  return { reached: false };
}

const validDomain = d => typeof d === "string" && d.length <= 253 && /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/.test(d);

async function reputation(domain){
  domain = String(domain || "").trim().toLowerCase();
  if(!validDomain(domain)) throw new Error("invalid domain");
  const [mal, mail, web] = await Promise.all([
    malware(domain).then(r => r.checked ? r : malware("www." + domain)).catch(() => ({ checked: false })),
    mailBlocklists(domain).catch(() => ({ checked: false })),
    website(domain).catch(() => ({ reached: false }))
  ]);
  return { domain, malware: mal, mailBlocklists: mail, web };
}

module.exports = { reputation, validDomain, MIN_WP };
