'use strict';

function ipv4(text) {
  const pieces = text.split('.');
  if (pieces.length !== 4 || pieces.some(x => !/^\d{1,3}$/.test(x) || +x > 255 || (x.length > 1 && x[0] === '0'))) throw new Error('Некоректна IPv4-адреса: ' + text);
  return pieces.reduce((n, x) => ((n << 8) | +x) >>> 0, 0);
}
function ipText(n) { return [24, 16, 8, 0].map(b => (n >>> b) & 255).join('.'); }
function cidr(text) {
  const parts = text.split('/');
  if (parts.length !== 2 || !/^\d{1,2}$/.test(parts[1]) || +parts[1] > 32) throw new Error('Некоректна підмережа: ' + text);
  const ip = ipv4(parts[0]), prefix = +parts[1], mask = prefix ? (0xffffffff << (32 - prefix)) >>> 0 : 0;
  return { ip, prefix, mask, network: (ip & mask) >>> 0 };
}
function chooseTunnelAddress(value) {
  const tokens = value.split(',').map(x => x.trim());
  if (tokens.some(x => !x)) throw new Error('Некоректний рядок Address.');
  const ipv4List = tokens.filter(x => !x.includes(':')).map(x => cidr(x.includes('/') ? x : x + '/32'));
  const hosts = ipv4List.filter(x => x.ip !== x.network || x.prefix === 32);
  if (hosts.length !== 1) throw new Error('Address повинен містити одну адресу WT32. LAN-маршрут не є адресою тунелю.');
  const ignored = tokens.length - 1;
  return { address: hosts[0], ignored };
}
function parseWireGuard(text) {
  if (text.length > 8192) throw new Error('Конфігурація завелика (максимум 8 КБ).');
  const sections = { Interface: {}, Peer: {} };
  const seen = new Set(); let section = '';
  for (let line of text.replace(/^\uFEFF/, '').split(/\r?\n/)) {
    line = line.replace(/\s*[#;].*$/, '').trim();
    if (!line) continue;
    if (line.startsWith('[')) {
      const m = /^\[(Interface|Peer)\]$/.exec(line);
      if (!m || seen.has(m[1])) throw new Error('Підтримується один [Interface] та один [Peer].');
      section = m[1]; seen.add(section); continue;
    }
    const m = /^([A-Za-z]+)\s*=\s*(.+)$/.exec(line);
    if (!section || !m || Object.hasOwn(sections[section], m[1])) throw new Error('Некоректний або повторений параметр у .conf.');
    sections[section][m[1]] = m[2].trim();
  }
  const i = sections.Interface, p = sections.Peer;
  for (const k of Object.keys(i)) if (!['PrivateKey','Address','DNS','MTU','ListenPort'].includes(k)) throw new Error('Параметр ' + k + ' не підтримується. Команди PostUp/PreUp не виконуються.');
  for (const k of Object.keys(p)) if (!['PublicKey','PresharedKey','Endpoint','AllowedIPs','PersistentKeepalive'].includes(k)) throw new Error('Параметр ' + k + ' не підтримується.');
  if (!i.PrivateKey || !i.Address || !p.PublicKey || !p.Endpoint) throw new Error('Потрібні PrivateKey, Address, PublicKey та Endpoint.');
  const keyPattern = /^[A-Za-z0-9+/]{43}=$/;
  for (const key of [i.PrivateKey,p.PublicKey,...(p.PresharedKey ? [p.PresharedKey] : [])]) if (!keyPattern.test(key)) throw new Error('Ключ WireGuard має містити 44 символи Base64.');
  const endpoint = /^([a-zA-Z0-9.-]+):(\d{1,5})$/.exec(p.Endpoint);
  if (!endpoint || +endpoint[2] < 1 || +endpoint[2] > 65535) throw new Error('Endpoint має бути IPv4-адресою або доменом з портом: vpn.example.com:51820.');
  const chosen = chooseTunnelAddress(i.Address), address = chosen.address;
  let remote = p.AllowedIPs && !p.AllowedIPs.includes(',') && !p.AllowedIPs.includes(':') ? cidr(p.AllowedIPs) : null;
  const warnings = [];
  if (chosen.ignored) warnings.push('У Address використано лише адресу WT32 ' + ipText(address.ip) + '. Додаткові адреси або LAN-маршрути пропущено.');
  if (!remote || remote.prefix < 8 || remote.prefix > 30 || (address.ip & remote.mask) >>> 0 !== remote.network) {
    const prefix = address.prefix >= 8 && address.prefix <= 30 ? address.prefix : 24;
    remote = cidr(ipText(address.ip) + '/' + prefix);
    warnings.push('Замість маршруту AllowedIPs запропоновано VPN-підмережу ' + ipText(remote.network) + '/' + remote.prefix + '. Перевірте її за налаштуваннями сервера.');
  }
  if (i.DNS) warnings.push('DNS із файлу не застосовується: WT32 використовує DNS локальної мережі.');
  if (i.ListenPort && +i.ListenPort !== 51820) warnings.push('Локальний ListenPort WT32 — 51820; порт сервера з Endpoint збережено.');
  const keepalive = p.PersistentKeepalive === undefined ? 25 : Number(p.PersistentKeepalive);
  const mtu = i.MTU === undefined ? 1280 : Number(i.MTU);
  if (!Number.isInteger(keepalive) || keepalive < 0 || keepalive > 120) throw new Error('PersistentKeepalive має бути від 0 до 120.');
  if (!Number.isInteger(mtu) || mtu < 1280 || mtu > 1420) throw new Error('MTU має бути від 1280 до 1420.');
  return { values: { private_key:i.PrivateKey,public_key:p.PublicKey,preshared_key:p.PresharedKey || '',clear_psk:!p.PresharedKey,
    address:ipText(address.ip),remote_cidr:ipText(remote.network)+'/'+remote.prefix,endpoint:endpoint[1],port:+endpoint[2],keepalive,mtu,enabled:true }, warnings };
}
function peerRecommendations(addressText, vpnText, lanText, key = '') {
  const address = ipv4(addressText), vpn = cidr(vpnText), lan = cidr(lanText);
  if (vpn.prefix < 8 || vpn.prefix > 29 || lan.prefix < 8 || lan.prefix > 30 || lan.network !== lan.ip || vpn.network !== vpn.ip) throw new Error('Для прикладів потрібні коректні VPN /8…/29 та LAN /8…/30.');
  if (((address & vpn.mask) >>> 0) !== vpn.network || address === vpn.network || address === ((vpn.network | (~vpn.mask)) >>> 0)) throw new Error('IP WT32 має належати VPN-підмережі.');
  const sharedMask = (vpn.mask & lan.mask) >>> 0;
  if ((vpn.network & sharedMask) === (lan.network & sharedMask)) throw new Error('VPN і LAN-підмережі перетинаються.');
  const clients = [];
  for (let host = vpn.network + 2; host < vpn.network + Math.min(256, 2 ** (32 - vpn.prefix)) - 1 && clients.length < 2; host++) {
    if (host !== address) clients.push(ipText(host));
  }
  if (clients.length < 2) throw new Error('VPN-підмережа замала для WT32 та двох клієнтів.');
  const suffix = vpnText + ', ' + lanText;
  return {
    wt32: 'PublicKey = ' + (key || '<публічний ключ WT32 після імпорту>') + '\nAllowed IPs = ' + addressText + '/32, ' + lanText + '\nEndpoint Allowed IPs = ' + vpnText,
    client1: 'Allowed IPs = ' + clients[0] + '/32\nEndpoint Allowed IPs = ' + suffix,
    client2: 'Allowed IPs = ' + clients[1] + '/32\nEndpoint Allowed IPs = ' + suffix,
    clients
  };
}
if (typeof module !== 'undefined') module.exports = { ipv4, ipText, cidr, chooseTunnelAddress, parseWireGuard, peerRecommendations };

if (typeof document !== 'undefined') {
  const $ = id => document.getElementById(id);
  let saved = {}, currentStatus = {}, busy = false, loaded = false, importNeedsConfirmation = false, previewKey = '', previewTimer;
  const fields = ['ssid','wifi_password','lan_cidr','address','remote_cidr','endpoint','port','public_key','private_key','preshared_key','keepalive','mtu','admin_user','admin_password','ap_ssid','ap_password','ap_timeout'];
  const booleans = ['enabled','clear_psk','open_wifi'];
  function message(text, error = false) { $('message').textContent = text; $('message').classList.toggle('error', error); $('message').hidden = false; }
  async function api(path, data) {
    const response = await fetch(path, { credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(10000),
      ...(data !== undefined ? {method:'POST',headers:{'Content-Type':'application/json','X-WT32-Request':'1'},body:JSON.stringify(data)} : {}) });
    const text = await response.text(); let json;
    try { json = JSON.parse(text); } catch { throw new Error(response.status === 401 ? 'Перевірте логін і пароль адміністратора.' : 'Панель недоступна або запит не виконано.'); }
    if (!response.ok) throw new Error(json.error || 'Не вдалося виконати запит.');
    return json;
  }
  function bytes(n) { return n < 1024 ? n + ' Б' : n < 1048576 ? (n/1024).toFixed(1) + ' КБ' : (n/1048576).toFixed(2) + ' МБ'; }
  function fill(values) {
    for (const id of fields) if (values[id] !== undefined) $(id).value = values[id];
    for (const id of booleans) if (values[id] !== undefined) $(id).checked = values[id];
    if (values.mode) { const radio = document.querySelector('input[name="mode"][value="'+values.mode+'"]'); if (radio) radio.checked = true; }
    updateMode(); updateRoutes();
  }
  function updateMode() {
    const mode = document.querySelector('input[name="mode"]:checked').value;
    $('wifi-fields').hidden = mode === 'eth';
    $('ssid').required = mode === 'wifi';
    $('mode-hint').textContent = mode === 'auto' ? 'Кабель має пріоритет. Wi-Fi підхопить з’єднання, якщо кабель відключиться.' : mode === 'eth' ? 'Використовується лише кабель. Наступні кроки доступні і без підключення.' : 'Використовується Wi-Fi 2,4 ГГц. Наступні кроки доступні і без підключення.';
  }
  function updateRoutes() {
    const manualLan = $('lan_cidr').value.trim(), lan = manualLan || currentStatus.lan || '';
    $('lan_cidr').placeholder = currentStatus.lan || '192.168.15.0/24';
    $('lan-source').textContent = manualLan ? (currentStatus.lan && manualLan !== currentStatus.lan ? 'Увага: задана підмережа відрізняється від виявленої ' + currentStatus.lan + '. Перед збереженням перевірте мережу.' : 'Підмережу задано вручну. Для автоматичного режиму очистіть поле або натисніть «Визначити автоматично».') : currentStatus.lan ? 'Автоматично виявлено ' + currentStatus.lan + '. Вона оновиться при зміні мережі.' : 'WT32 ще не підключена. Введіть підмережу вручну для підготовки маршрутів.';
    try {
      const key = previewKey || ($('private_key').value.trim() ? '' : saved.device_public_key || '');
      const plan = peerRecommendations($('address').value.trim(), $('remote_cidr').value.trim(), lan, key);
      for (const name of ['wt32','client1','client2']) $('peer-'+name).textContent = plan[name];
      $('route-state').textContent = 'Приклади для LAN ' + lan + '. Перед застосуванням перевірте VPN-адреси клієнтів і ключ WT32.';
      for (const button of document.querySelectorAll('.copy-peer')) button.disabled = button.dataset.peer === 'wt32' && !key;
    } catch (error) {
      for (const name of ['wt32','client1','client2']) $('peer-'+name).textContent = '—';
      $('route-state').textContent = error.message;
      for (const button of document.querySelectorAll('.copy-peer')) button.disabled = true;
    }
  }
  async function refreshPreviewKey() {
    const key = $('private_key').value.trim();
    if (!key) { previewKey = ''; updateRoutes(); return; }
    try { const result = await api('/api/key', {private_key:key}); if ($('private_key').value.trim() === key) { previewKey = result.public_key; updateRoutes(); } } catch { previewKey = ''; updateRoutes(); }
  }
  async function poll() {
    if (busy) { setTimeout(poll, 4000); return; }
    try {
      currentStatus = await api('/api/status'); const s = currentStatus;
      $('device-dot').classList.add('online'); $('device-state').textContent = 'Панель доступна';
      $('uplink').textContent = s.uplink;
      $('uplink-note').textContent = s.uplink === 'Wi-Fi' ? 'Сигнал '+s.rssi+' dBm · 2,4 ГГц' : s.uplink === 'Ethernet' ? 'Підключено кабелем' : 'Підключіть кабель або Wi-Fi';
      $('lan').textContent = s.lan || '—'; $('local-ip').textContent = s.ip ? 'Адреса WT32: '+s.ip : 'Очікування DHCP';
      $('traffic').textContent = bytes(s.rx_bytes+s.tx_bytes); $('traffic-detail').textContent = '↓ '+bytes(s.rx_bytes)+' до LAN   ↑ '+bytes(s.tx_bytes)+' у VPN';
      $('vpn-badge').textContent = s.tunnel ? 'ТУНЕЛЬ АКТИВНИЙ' : 'НЕ ПІДКЛЮЧЕНО';
      $('vpn-title').textContent = s.tunnel ? 'Ви на зв’язку.' : saved.enabled ? 'Встановлюємо з’єднання' : 'Підключіть вашу мережу';
      $('vpn-detail').textContent = s.state + '.';
      $('ap-state').textContent = s.ap ? (s.ap_clients ? 'Клієнтів: '+s.ap_clients+'; точка залишається активною.' : 'Без клієнтів. Вимкнення через '+s.ap_remaining+' с.') : 'Точку вимкнено до наступного перезапуску.';
      $('uptime').textContent = 'Час роботи: '+Math.floor(s.uptime/3600)+' год '+Math.floor(s.uptime%3600/60)+' хв';
      updateRoutes();
    } catch {
      $('device-dot').classList.remove('online'); $('device-state').textContent = 'Немає зв’язку з WT32';
      $('vpn-badge').textContent = 'СТАТУС НЕВІДОМИЙ'; $('vpn-title').textContent = 'Зв’язок із панеллю втрачено';
      $('vpn-detail').textContent = 'Перевірте підключення. Показники нижче — останні отримані.';
    }
    setTimeout(poll, 4000);
  }
  $('conf-file').addEventListener('change', async event => {
    const file = event.target.files[0]; if (!file) return;
    try {
      if (file.size > 8192) throw new Error('Конфігурація завелика (максимум 8 КБ).');
      const parsed = parseWireGuard(await file.text()); fill(parsed.values);
      importNeedsConfirmation = parsed.warnings.length > 0;
      $('confirm_import').checked = false;
      $('import-notice').hidden = !importNeedsConfirmation;
      $('import-message').textContent = parsed.warnings.join(' ');
      $('keys').open = true;
      refreshPreviewKey();
      message('Конфігурацію імпортовано. Перевірте поля та попередження й натисніть «Зберегти налаштування».');
    } catch (error) { message(error.message, true); }
    event.target.value = '';
  });
  for (const input of document.querySelectorAll('input[name="mode"]')) input.addEventListener('change', updateMode);
  for (const id of ['lan_cidr','address','remote_cidr']) $(id).addEventListener('input', updateRoutes);
  $('detect-lan').addEventListener('click', () => { if (!currentStatus.lan) return message('WT32 ще не отримала IP. Введіть підмережу вручну.', true); $('lan_cidr').value = ''; updateRoutes(); message('Використовується автоматично виявлена підмережа '+currentStatus.lan+'.'); });
  $('private_key').addEventListener('input', () => { previewKey = ''; updateRoutes(); clearTimeout(previewTimer); previewTimer = setTimeout(refreshPreviewKey, 500); });
  for (const button of document.querySelectorAll('.copy-peer')) button.addEventListener('click', async () => {
    const content = $('peer-'+button.dataset.peer).textContent;
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(content);
      else { const temp = document.createElement('textarea'); temp.value = content; document.body.append(temp); temp.select(); const copied = document.execCommand('copy'); temp.remove(); if (!copied) throw new Error(); }
      message('Параметри скопійовано. Додайте їх у відповідний peer на сервері.');
    } catch { message('Скопіюйте текст вручну.', true); }
  });
  $('settings').addEventListener('submit', async event => {
    event.preventDefault(); if (busy || !loaded) return;
    try {
      if (importNeedsConfirmation && !$('confirm_import').checked) throw new Error('Перевірте повідомлення імпорту та поставте позначку.');
      const values = { mode: document.querySelector('input[name="mode"]:checked').value };
      for (const id of fields) values[id] = ['port','keepalive','mtu','ap_timeout'].includes(id) ? Number($(id).value) : $(id).value.trim();
      for (const id of booleans) values[id] = $(id).checked;
      if (values.lan_cidr) { const lan = cidr(values.lan_cidr); if (lan.network !== lan.ip) throw new Error('Вкажіть адресу підмережі, наприклад 192.168.15.0/24.'); }
      if (values.enabled) { ipv4(values.address); cidr(values.remote_cidr); }
      busy = true; $('save').disabled = true; $('save').textContent = 'Збереження…';
      await api('/api/config', values);
      message('Збережено. WT32 перезапускається. Через 15 секунд оновіть сторінку та, якщо потрібно, увійдіть з новими даними.');
      $('save').textContent = 'Збережено · перезапуск';
    } catch (error) { busy = false; $('save').disabled = false; $('save').textContent = 'Зберегти налаштування ↗'; message(error.message, true); }
  });
  for (const link of document.querySelectorAll('nav a')) link.addEventListener('click', () => document.querySelectorAll('nav a').forEach(a => a.classList.toggle('active', a === link)));
  async function pollScan() {
    try {
      const s = await api('/api/scan');
      $('scan-progress').textContent = s.error || (s.running ? 'Перевірено '+s.progress+' із '+s.total+' адрес…' : s.total ? 'Готово. Знайдено '+s.hosts.length+' пристроїв.' : 'Сканування ще не запускалося.');
      $('scan-start').disabled = s.running;
      $('scan-results').replaceChildren(...s.hosts.map(host => { const row=document.createElement('div'); row.className='scan-row'; const ip=document.createElement('strong'); ip.textContent=host.ip; const mac=document.createElement('span'); mac.textContent=host.mac; row.append(ip,mac); return row; }));
      if (s.running) setTimeout(pollScan, 1500);
    } catch (error) { $('scan-progress').textContent = error.message; $('scan-start').disabled = false; }
  }
  $('scan-start').addEventListener('click', async () => { try { await api('/api/scan',{}); $('scan-start').disabled = true; pollScan(); } catch(error) { message(error.message,true); pollScan(); } });
  async function load() {
    try {
      saved = await api('/api/config'); fill(saved); loaded = true; $('save').disabled = false;
      $('setup-ssid').textContent = saved.setup_ssid;
      for (const [id,flag] of [['private_key','has_private_key'],['wifi_password','has_wifi_password'],['preshared_key','has_psk'],['ap_password','has_ap_password']]) if (saved[flag]) $(id).placeholder = 'Збережено · порожнє поле залишить без змін';
      $('keys').open = !saved.has_private_key;
    } catch (error) { message(error.message+' Оновіть сторінку для повторної спроби.', true); }
    poll(); pollScan();
  }
  load();
}
