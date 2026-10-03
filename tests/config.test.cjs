const test = require('node:test');
const assert = require('node:assert/strict');
const {ipv4, cidr, parseWireGuard, peerRecommendations} = require('../main/web/app.js');
const key = Buffer.alloc(32, 1).toString('base64');
const base = `[Interface]\nPrivateKey = ${key}\nAddress = 10.7.0.2/32\n[Peer]\nPublicKey = ${key}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 10.7.0.0/24\n`;
test('imports a routed VPN peer and preserves base64 padding', () => {
  const result = parseWireGuard(base);
  assert.equal(result.values.private_key, key);
  assert.equal(result.values.remote_cidr, '10.7.0.0/24');
  assert.equal(result.values.port, 51820);
  assert.equal(result.values.keepalive, 25);
  assert.deepEqual(result.warnings, []);
});
test('default route requires explicit subnet review', () => {
  const result = parseWireGuard(base.replace('10.7.0.0/24', '0.0.0.0/0'));
  assert.equal(result.values.remote_cidr, '10.7.0.0/24');
  assert.equal(result.warnings.length, 1);
});
test('multiple allowed routes require review instead of silently enabling an exit node', () => {
  assert.equal(parseWireGuard(base.replace('10.7.0.0/24','0.0.0.0/0, ::/0')).warnings.length, 1);
});
test('rejects duplicate peers, keys, executable directives and IPv6 endpoints', () => {
  for (const text of [base+'[Peer]\n',base+'PublicKey = '+key,base.replace('[Peer]','PostUp = reboot\n[Peer]'),base.replace('vpn.example.com:51820','[::1]:51820')]) assert.throws(() => parseWireGuard(text));
});
test('validates port, MTU, keepalive and key length', () => {
  for (const text of [base.replace(':51820',':0'),base.replace(':51820',':65536'),base+'PersistentKeepalive = -1',base.replace('[Peer]','MTU = 1500\n[Peer]'),base.replace(key,'bad-key')]) assert.throws(() => parseWireGuard(text));
});
test('allows BOM, CRLF, comments, PSK and keepalive zero', () => {
  const result = parseWireGuard('\uFEFF'+base.replaceAll('\n','\r\n')+`PresharedKey = ${key} # note\nPersistentKeepalive = 0`);
  assert.equal(result.values.keepalive, 0);
  assert.equal(result.values.preshared_key, key);
  assert.equal(result.values.clear_psk, false);
});
test('an imported config without a PSK removes a previous PSK', () => assert.equal(parseWireGuard(base).values.clear_psk, true));
test('WGDashboard export with a LAN route in Address selects only the WT32 host', () => {
  const result = parseWireGuard(base.replace('Address = 10.7.0.2/32', 'Address = 10.7.0.2/32, 192.168.15.0/24'));
  assert.equal(result.values.address, '10.7.0.2');
  assert.equal(result.values.remote_cidr, '10.7.0.0/24');
  assert.match(result.warnings.join(' '), /LAN-маршрути/);
});
test('dual-stack Address selects IPv4 and warns about ignored IPv6', () => {
  const result = parseWireGuard(base.replace('Address = 10.7.0.2/32', 'Address = 10.7.0.2/32, fd00:7::2/128'));
  assert.equal(result.values.address, '10.7.0.2');
  assert.equal(result.warnings.length, 1);
});
test('rejects two candidate tunnel IPv4 addresses', () => {
  assert.throws(() => parseWireGuard(base.replace('Address = 10.7.0.2/32', 'Address = 10.7.0.2/32, 10.7.0.3/32')));
});
test('generates distinct server and endpoint routes for WT32 and two clients', () => {
  const plan = peerRecommendations('192.168.192.2','192.168.192.0/24','192.168.15.0/24','test-key');
  assert.match(plan.wt32,/Allowed IPs = 192\.168\.192\.2\/32, 192\.168\.15\.0\/24/);
  assert.match(plan.wt32,/Endpoint Allowed IPs = 192\.168\.192\.0\/24/);
  assert.match(plan.client1,/Allowed IPs = 192\.168\.192\.3\/32/);
  assert.match(plan.client2,/Allowed IPs = 192\.168\.192\.4\/32/);
  assert.match(plan.client1,/Endpoint Allowed IPs = 192\.168\.192\.0\/24, 192\.168\.15\.0\/24/);
});
test('strict IPv4 and prefix validation', () => {
  for (const ip of ['256.0.0.1','1.2.3','10.0.0.-1','010.0.0.1']) assert.throws(() => ipv4(ip));
  for (const range of ['10.0.0.1/33','10.0.0.1/x','10.0.0.1/','10.0.0.1']) assert.throws(() => cidr(range));
  assert.equal(cidr('192.168.10.7/24').network, ipv4('192.168.10.0'));
});
