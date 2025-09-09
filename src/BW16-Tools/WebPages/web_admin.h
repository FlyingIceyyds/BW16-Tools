#ifndef WEB_ADMIN_H
#define WEB_ADMIN_H

// Tabbed Web UI: Home + Custom SSID Beacon (keeps original endpoints)
const char WEB_ADMIN_HTML[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>BW16 Web UI</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:Arial,Helvetica,sans-serif;background:#f5f6f8;color:#222;padding:16px}
    .shell{max-width:800px;margin:0 auto;background:#fff;border:1px solid #e8e8e8;border-radius:10px;box-shadow:0 2px 8px rgba(0,0,0,.06);overflow:hidden}
    .brand{padding:16px 18px;border-bottom:1px solid #eee;background:linear-gradient(180deg,#4caf50,#45a049);color:#fff}
    .brand h1{font-size:18px;margin:0}
    .tabs{display:flex;gap:0;border-bottom:1px solid #eee;background:#fafafa}
    .tab{flex:1;text-align:center;padding:12px 10px;cursor:pointer;font-weight:600;color:#555}
    .tab.active{background:#fff;border-bottom:2px solid #4caf50;color:#2e7d32}
    .page{display:none;padding:16px}
    .page.active{display:block}
    h2{font-size:16px;margin-bottom:8px;color:#333;display:flex;flex-wrap:nowrap;justify-content:center}
    p{margin:8px 0;color:#555;line-height:1.5}
    .card{border:1px solid #eee;border-radius:8px;padding:12px;background:#fafafa}
    #HomeCard{display:flex;justify-content:center;flex-wrap:wrap}
    label{display:block;color:#444;font-size:14px;margin-top:6px}
    input[type=text]{width:100%;padding:10px;margin:6px 0;border:1px solid #ccc;border-radius:6px}
    .row{margin-top:8px;text-align:center}
    .btn{padding:10px 14px;border:0;border-radius:6px;color:#fff;cursor:pointer;margin-right:8px;display:inline-block}
    .btn-danger{background:#f44336}
    .btn-warning{background:#ff9800}
    .status{margin-top:10px;padding:10px;border-radius:6px;background:#e8f5e9;border:1px solid #4caf50;color:#2e7d32;text-align:center}
    .muted{color:#777;font-size:12px;margin-top:8px}
    .radio-row{ text-align:center; }
    .radio-row>label{display:inline-block;margin-right:12px}
    .muted{text-align:center}
    footer{padding:12px;text-align:center;color:#999;border-top:1px solid #eee;font-size:12px}
  </style>
  <script>
    function $(id){return document.getElementById(id)}
    function setActive(idx){
      const tabs=document.querySelectorAll('.tab');
      const pages=document.querySelectorAll('.page');
      tabs.forEach((t,i)=>t.classList.toggle('active', i===idx));
      pages.forEach((p,i)=>p.classList.toggle('active', i===idx));
    }
    function show(msg,type){
      const d=document.createElement('div');
      d.textContent=msg; d.className='toast';
      d.style.cssText='position:fixed;left:50%;top:16px;transform:translateX(-50%);background:'+(type==='success'?'#4caf50':'#f44336')+';color:#fff;padding:8px 12px;border-radius:6px;box-shadow:0 4px 10px rgba(0,0,0,.2);z-index:9999;';
      document.body.appendChild(d); setTimeout(()=>d.remove(),2000);
    }
    function startCustom(){
      const ssid=$('ssid').value.trim(); if(!ssid){show('请输入SSID');return}
      if(!confirm('点击确定将提交攻击请求，同时会关闭当前接入点。停止Web UI可结束攻击')) return;
      const band=document.querySelector('input[name="band"]:checked').value;
      const body='ssid='+encodeURIComponent(ssid)+'&band='+encodeURIComponent(band);
      try { fetch('/custom-beacon',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body}); } catch(e) {}
      show('已开始攻击，将断开此接入点连接！');
    }
    function stopAll(){
      fetch('/stop',{method:'POST'}).then(r=>r.json()).then(()=>{ show('已停止','success'); })
        .catch(()=>show('请求失败'))
    }
    document.addEventListener('DOMContentLoaded', ()=>{ setActive(0); refresh(); setInterval(refresh,2000); });
  </script>
</head>
<body>
  <div class="shell">
    <div class="brand"><h1>BW16 Tools · Web UI</h1></div>
    <div class="tabs">
      <div class="tab active" onclick="setActive(0)">首页</div>
      <div class="tab" onclick="setActive(1)">自定义信标攻击</div>
    </div>
    <div class="page active" id="page-home">
      <h2>关于本项目</h2>
      <div class="card" id="HomeCard">
        <p>github.com/FlyingIceyyds/Bw16-Tools</p>
        <p>采用GPL-3.0协议开源，请勿将此项目及其衍生作品用作商业用途，严禁倒卖固件！</p>
      </div>
      <h2 style="margin-top:14px;">Web UI说明</h2>
      <div class="status">当前版本Web UI仅包含OLED菜单无法操作的功能，不添加重复功能</div>
    </div>
    <div class="page" id="page-beacon">
      <h2>自定义 SSID 信标帧攻击</h2>
      <div class="card">
        <label>SSID 名称</label>
        <input id="ssid" type="text" placeholder="输入要广播的 SSID">
        <label style="margin-top:8px;">频段</label>
        <div class="radio-row">
          <label><input type="radio" name="band" value="mixed" checked> 混合(2.4G+5G)</label>
          <label><input type="radio" name="band" value="2g"> 2.4G</label>
          <label><input type="radio" name="band" value="5g"> 5G</label>
        </div>
        <div class="row">
          <button class="btn btn-danger" onclick="startCustom()">开始</button>
          <button class="btn btn-warning" onclick="stopAll()">停止</button>
        </div>
        <div class="muted">Web UI会占用部分资源，可能影响攻击效率。如非必要建议使用OLED菜单</div>
      </div>
    </div>
    <footer>© 2025 Bw16-Tools</footer>
  </div>
</body>
</html>
)rawliteral";

#endif



