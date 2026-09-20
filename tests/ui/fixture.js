/* Local-only fixture. No network fallback: unknown requests fail closed. */
(function () {
  var clone = function (v) { return JSON.parse(JSON.stringify(v)); };
  var accounts = ['codex-demo-a-pro.json', 'codex-demo-b-pro.json', 'codex-demo-c-pro.json'];
  var models = ['gpt-5.5', 'gpt-5.6-sol', 'gpt-5.6-terra', 'gpt-6-astra'];
  function initial() {
    var buckets = [];
    [[52,43,0,38],[49,0,7,0],[54,46,0,51]].forEach(function(row,i){
      row.forEach(function(min,j){buckets.push({auth_id:accounts[i],model:models[j],ready:min>0,len:min?292:0,seconds_left:min*60,issued_at:new Date(Date.now()-(60-min)*60000).toISOString(),expires_at:new Date(Date.now()+min*60000).toISOString(),attribution:'observed'});});
    });
    return {role:'business',dry_run:false,inject_mode:'always',ttl_seconds:3600,template_length:292,replace_length:312,store_dir:'/data/turn-state-store',models:models.slice(),probe_accounts:accounts.slice(),buckets:buckets,targets_total:12,targets_ready:8,accounts_source:'host',counters:{harvest:24,substitute:108,pass:1614,skip:0},counters_since:new Date(Date.now()-3600000).toISOString(),probe_proxy_count:2,probe_proxies:['socks5h://user:example@static-01.example:1080','http://user:example@static-02.example:8080'],probe_proxy_rotating_count:4,probe_proxies_rotating:[1,2,3,4].map(function(i){return 'http://user:example@rotating-0'+i+'.example:8080';}),config_errors:[],probe_run:{running:true,total:12,done:12,started_at:new Date(Date.now()-120000).toISOString(),current:'renewal active',lines:['14:30:48 initial fill done; renewal active','14:31:06 demo-c gpt-6-astra: harvested len=292, fresh template stored','14:32:08 nothing due; next check in 1m0s']}};
  }
  window.__mock = {status:initial(),requests:[],failNext:null,reset:function(){this.status=initial();this.requests=[];this.failNext=null;}};
  window.fetch = function (input, options) {
    var u = new URL(String(input),location.href), prefix='/v0/resource/plugins/codex-turn-state';
    if(u.origin!==location.origin || !u.pathname.startsWith(prefix+'/')) return Promise.reject(new Error('Preview blocked unexpected request'));
    var path=u.pathname.slice(prefix.length),q=u.searchParams,m=window.__mock,s=m.status;
    m.requests.push({path:path,query:Array.from(q.entries()),method:(options||{}).method||'GET'});
    function response(body,status){return Promise.resolve(new Response(JSON.stringify(clone(body)),{status:status||200,headers:{'Content-Type':'application/json'}}));}
    if(m.failNext===path){m.failNext=null;return response({error:'Simulated failure'},503);}
    if(path==='/status') return response(s);
    if(path==='/ops/choices') return response({source:'host',accounts:accounts.concat(['codex-demo-disabled-pro.json']).map(function(a,i){return {name:a,label:'账号 '+String.fromCharCode(65+i)+' · Pro',disabled:i===3,selected:s.probe_accounts.indexOf(a)>=0};}),models:models.map(function(n){return {name:n,label:n,selected:s.models.indexOf(n)>=0};})});
    if(q.get('confirm')!=='1') return response({error:'Missing confirmation'},400);
    if(path==='/ops/scope'){
      q.get('fields').split(',').forEach(function(f){var spec={accounts:['probe_accounts','account'],models:['models','model'],proxies:['probe_proxies','proxy'],rotating:['probe_proxies_rotating','rotating_proxy']}[f];if(spec)s[spec[0]]=q.getAll(spec[1]);});
      s.probe_proxy_count=s.probe_proxies.length;s.probe_proxy_rotating_count=s.probe_proxies_rotating.length;
      return response({saved:true});
    }
    if(path==='/ops/dry-run'){s.dry_run=q.get('value')==='on';return response({dry_run:s.dry_run});}
    if(path==='/ops/role'){s.role=q.get('value');return response({role:s.role});}
    if(path==='/ops/probe/cancel'){s.probe_run.running=false;s.probe_run.finished_at=new Date().toISOString();return response({cancelled:true});}
    if(path==='/ops/probe/start'){s.probe_run.running=true;return response({started:true});}
    if(path==='/ops/clear'){var before=s.buckets.length;s.buckets=s.buckets.filter(function(b){return q.get('all')!=='1' && (b.auth_id!==q.get('auth_id')||b.model!==q.get('model'));});return response({cleared:before-s.buckets.length});}
    if(path==='/ops/selftest')return response({reached:true,ok:true,status_code:200,targeted:!!q.get('auth_id'),auth_id:q.get('auth_id')||'',model:q.get('model'),harvested:false});
    if(path==='/ops/proxy-check')return response({checked:2,ok:1,dead:1,ms:850,static_checked:2,distinct_ips:1,results:[{index:1,verdict:'ok',pool:'static',status_code:401,ms:100,exit_ip:'192.0.2.10',country:'US',proxy:'socks5h://***@static-01.example:1080'},{index:2,verdict:'dead',pool:'static',ms:750,detail:'Synthetic connection timeout',proxy:'http://***@static-02.example:8080'}]});
    return response({error:'Unimplemented preview action'},404);
  };
})();
