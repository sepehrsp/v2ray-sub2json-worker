import { describe, test, expect } from 'vitest';
import { convert } from '$lib/utils/conversion';
import { decodeBase64, isValidShadowsocksUrl4XRAY, classifySubInput, logSafeUrl } from '$lib/utils/helpers';

const VLESS_TCP =
	'vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=none';
const VLESS_WS_TLS =
	'vless://11111111-1111-1111-1111-111111111111@example.com:443?type=ws&security=tls&sni=example.com&fp=chrome&path=%2Fws&host=example.com';
const VLESS_GRPC_REALITY =
	'vless://11111111-1111-1111-1111-111111111111@example.com:443?type=grpc&security=reality&sni=example.com&fp=chrome&pbk=abcd&sid=abcd&spx=%2F';
const VLESS_HTTPUPGRADE_TLS =
	'vless://11111111-1111-1111-1111-111111111111@example.com:443?type=httpupgrade&security=tls&sni=example.com&fp=chrome';
const TROJAN_TLS = 'trojan://password@example.com:443?type=tcp&security=tls&sni=example.com';
const SS_URL =
	'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA==@example.com:8388';
const WIREGUARD =
	'wireguard://1.2.3.4:51820?type=wireguard&publickey=pubkey&secretkey=seckey&address=10.0.0.2';

const VMESS_TCP_B64 = btoa(
	JSON.stringify({
		add: 'example.com',
		id: '11111111-1111-1111-1111-111111111111',
		net: 'tcp',
		port: '443',
		tls: 'none',
		type: '',
		path: ''
	})
);
const VMESS_TCP = `vmess://${VMESS_TCP_B64}`;

describe('convert', () => {
	test('converts a vless tcp URI into a proxy outbound wired into selectors', async () => {
		const result = await convert(VLESS_TCP);
		expect(result).not.toHaveProperty('error');

		const proxy = result.outbounds.find((o: { tag: string }) => o.tag === 'proxy-1');
		expect(proxy).toBeDefined();
		expect(proxy.protocol).toBe('vless');
		expect(proxy.settings.vnext[0].address).toBe('example.com');
		expect(proxy.settings.vnext[0].port).toBe(443);
		expect(proxy.settings.vnext[0].users[0].id).toBe('11111111-1111-1111-1111-111111111111');
		expect(proxy.settings.vnext[0].users[0].encryption).toBe('none');
		expect(proxy.streamSettings.network).toBe('tcp');
		expect(proxy.streamSettings.security).toBe('none');
		expect(proxy.mux).toEqual({ enabled: false, concurrency: -1 });

		expect(result.burstObservatory.subjectSelector).toContain('proxy-1');
		expect(result.routing.balancers[0].selector).toContain('proxy-1');
	});

	test('converts a vless ws+tls URI with sni/fp/path/host', async () => {
		const result = await convert(VLESS_WS_TLS);
		expect(result).not.toHaveProperty('error');
		const proxy = result.outbounds.find((o: { tag: string }) => o.tag === 'proxy-1');
		expect(proxy.streamSettings.network).toBe('ws');
		expect(proxy.streamSettings.security).toBe('tls');
		expect(proxy.streamSettings.tlsSettings.serverName).toBe('example.com');
		expect(proxy.streamSettings.tlsSettings.fingerprint).toBe('chrome');
		// pinned current behavior: allowInsecure true is inherited upstream
		expect(proxy.streamSettings.tlsSettings.allowInsecure).toBe(true);
		expect(proxy.streamSettings.wsSettings.path).toBe('/ws');
		expect(proxy.streamSettings.wsSettings.headers.Host).toBe('example.com');
	});

	test('converts a vless grpc+reality URI', async () => {
		const result = await convert(VLESS_GRPC_REALITY);
		expect(result).not.toHaveProperty('error');
		const proxy = result.outbounds.find((o: { tag: string }) => o.tag === 'proxy-1');
		expect(proxy.streamSettings.network).toBe('grpc');
		expect(proxy.streamSettings.security).toBe('reality');
		expect(proxy.streamSettings.realitySettings.serverName).toBe('example.com');
		expect(proxy.streamSettings.realitySettings.publicKey).toBe('abcd');
		expect(proxy.streamSettings.realitySettings.shortId).toBe('abcd');
		expect(proxy.streamSettings.realitySettings.spiderX).toBe('/');
	});

	test('converts a vless httpupgrade+tls URI', async () => {
		const result = await convert(VLESS_HTTPUPGRADE_TLS);
		expect(result).not.toHaveProperty('error');
		const proxy = result.outbounds.find((o: { tag: string }) => o.tag === 'proxy-1');
		expect(proxy.streamSettings.network).toBe('httpupgrade');
		expect(proxy.streamSettings.security).toBe('tls');
		// fixed (plan 002 finding 3): httpupgradeSettings now present
		expect(proxy.streamSettings.httpupgradeSettings).toBeDefined();
		expect(proxy.streamSettings.httpupgradeSettings.path).toBeDefined();
	});

	test('converts a trojan tcp+tls URI', async () => {
		const result = await convert(TROJAN_TLS);
		expect(result).not.toHaveProperty('error');
		const proxy = result.outbounds.find((o: { tag: string }) => o.tag === 'proxy-1');
		expect(proxy.protocol).toBe('trojan');
		expect(proxy.settings.servers[0].address).toBe('example.com');
		expect(proxy.settings.servers[0].port).toBe(443);
		expect(proxy.settings.servers[0].password).toBe('password');
		// fixed (plan 002 finding 1): level key removed (defaults to 0)
		expect(proxy.settings.servers[0]).not.toHaveProperty('level');
		expect(proxy.streamSettings.security).toBe('tls');
		// fixed (plan 002 finding 2): mux no longer attached to trojan
		expect(proxy.mux).toBeUndefined();
	});

	test('converts a shadowsocks URI', async () => {
		const result = await convert(SS_URL);
		expect(result).not.toHaveProperty('error');
		const proxy = result.outbounds.find((o: { tag: string }) => o.tag === 'proxy-1');
		expect(proxy.protocol).toBe('shadowsocks');
		expect(proxy.settings.servers[0].method).toBe('chacha20-ietf-poly1305');
		expect(proxy.settings.servers[0].password).toBe('password');
		expect(proxy.settings.servers[0].address).toBe('example.com');
		expect(proxy.settings.servers[0].port).toBe(8388);
		// fixed (plan 002 finding 2): mux no longer attached to shadowsocks
		expect(proxy.mux).toBeUndefined();
	});

	test('plain-form ss userinfo is mis-parsed (known-bug, unplanned)', async () => {
		// A plain `method:password` ss userinfo is base64-decoded by
		// conversion.ts even though it is not base64. Real ss links use base64.
		const result = await convert('ss://chacha20-ietf-poly1305:password@example.com:8388');
		expect(result).not.toHaveProperty('error');
		const proxy = result.outbounds.find((o: { tag: string }) => o.tag === 'proxy-1');
		expect(proxy.settings.servers[0].method).not.toBe('chacha20-ietf-poly1305');
	});

	test('converts a vmess tcp URI', async () => {
		const result = await convert(VMESS_TCP);
		expect(result).not.toHaveProperty('error');
		const proxy = result.outbounds.find((o: { tag: string }) => o.tag === 'proxy-1');
		expect(proxy.protocol).toBe('vmess');
		expect(proxy.settings.vnext[0].address).toBe('example.com');
		expect(proxy.settings.vnext[0].port).toBe(443);
		// known-bug (see plans/002): vmess TLS from the payload is dropped
		expect(proxy.streamSettings.security).toBe('none');
		expect(proxy.streamSettings.network).toBe('tcp');
	});

	test('converts a wireguard URI', async () => {
		const result = await convert(WIREGUARD);
		expect(result).not.toHaveProperty('error');
		const proxy = result.outbounds.find((o: { tag: string }) => o.tag === 'proxy-1');
		expect(proxy.protocol).toBe('wireguard');
		expect(proxy.settings.peers[0].publicKey).toBe('pubkey');
		expect(proxy.settings.peers[0].endpoint).toBe('1.2.3.4:51820');
		// fixed (plan 002 finding 6): secretKey read from secretkey param
		expect(proxy.settings.secretKey).toBe('seckey');
	});

	test('converts multiple lines and skips garbage', async () => {
		const result = await convert(`${VLESS_TCP}\nnot-a-uri\n`);
		expect(result).not.toHaveProperty('error');
		const proxies = result.outbounds.filter((o: { tag: string }) => o.tag.startsWith('proxy-'));
		expect(proxies.length).toBe(1);
		expect(result.burstObservatory.subjectSelector).toEqual(['proxy-1']);
		expect(result.routing.balancers[0].selector).toEqual(['proxy-1']);
	});

	test('returns error when no valid proxies found (empty input)', async () => {
		const result = await convert('');
		expect(result).toEqual({ error: 'No valid proxies found' });
	});

	test('returns error for a URI with an out-of-range port', async () => {
		const bad = 'vless://11111111-1111-1111-1111-111111111111@example.com:70000?type=tcp&security=none';
		const result = await convert(bad);
		expect(result).toEqual({ error: 'No valid proxies found' });
	});

	test('limit filters out non-matching protocols', async () => {
		const input = `${VLESS_TCP}\n${TROJAN_TLS}`;
		const result = await convert(input, ['trojan']);
		expect(result).not.toHaveProperty('error');
		const proxies = result.outbounds.filter((o: { tag: string }) => o.tag.startsWith('proxy-'));
		expect(proxies.map((p: { protocol: string }) => p.protocol)).toEqual(['trojan']);
	});

	test('limit reality drops a non-reality vless link', async () => {
		const result = await convert(VLESS_TCP, ['reality']);
		expect(result).toEqual({ error: 'No valid proxies found' });
	});

	test('a poisoned vmess:// line does not 500 the whole subscription', async () => {
		// regression for plan 002 finding 4: an unguarded decodeVmessUri used to
		// throw SyntaxError and make the entire request return HTTP 500.
		const result = await convert(`${VLESS_TCP}\nvmess://!!!`);
		expect(result).not.toHaveProperty('error');
		const proxies = result.outbounds.filter((o: { tag: string }) => o.tag.startsWith('proxy-'));
		expect(proxies.length).toBe(1);
	});

	test('a vmess line with a non-object body is skipped, not 500' , async () => {
		// regression for plan 002 finding 4/5: body that is not a valid vmess
		// object (e.g. non-string flow) must be skipped, not crash conversion.
		const body = btoa(JSON.stringify({ net: 'tcp', port: '443', flow: 123 }));
		const result = await convert(`${VLESS_TCP}\nvmess://${body}`);
		expect(result).not.toHaveProperty('error');
		const proxies = result.outbounds.filter((o: { tag: string }) => o.tag.startsWith('proxy-'));
		expect(proxies.length).toBe(1);
	});
});

describe('decodeBase64', () => {
	test('round-trips a known string', () => {
		const src = 'hello world';
		expect(decodeBase64(btoa(src))).toBe(src);
	});

	test('strips invalid characters without throwing', () => {
		expect(() => decodeBase64('a@@b')).not.toThrow();
	});

	test('handles missing padding', () => {
		expect(() => decodeBase64('eyJhZGQi')).not.toThrow();
	});

	test('matches btoa round-trip for clean input', () => {
		const src = '{"a":1,"b":"xyz"}';
		expect(decodeBase64(btoa(src))).toBe(src);
	});
});

describe('isValidShadowsocksUrl4XRAY', () => {
	test('accepts a supported method', () => {
		expect(isValidShadowsocksUrl4XRAY('ss://chacha20-ietf-poly1305:password@example.com:8388')).toBe(
			true
		);
	});

	test('accepts a 2022 method', () => {
		expect(
			isValidShadowsocksUrl4XRAY('ss://2022-blake3-aes-256-gcm:secretkey@example.com:8388')
		).toBe(true);
	});

	test('rejects an unsupported method', () => {
		expect(isValidShadowsocksUrl4XRAY('ss://aes-192-gcm:password@example.com:8388')).toBe(false);
	});

	test('rejects missing userinfo @', () => {
		expect(isValidShadowsocksUrl4XRAY('ss://example.com:8388')).toBe(false);
	});

	test('rejects a bad port', () => {
		expect(isValidShadowsocksUrl4XRAY('ss://chacha20-ietf-poly1305:password@example.com:99999')).toBe(
			false
		);
	});
});

describe('classifySubInput', () => {
	test('passes https URL through to fetchUrls', () => {
		const r = classifySubInput('https://sub.example.com/x');
		expect(r.fetchUrls).toEqual(['https://sub.example.com/x']);
		expect(r.proxyLines).toEqual([]);
		expect(r.skipped).toEqual([]);
		expect(r.tooLarge).toBe(false);
	});

	test('passes http URL through (mirror use case)', () => {
		const r = classifySubInput('http://sub.example.com/x');
		expect(r.fetchUrls).toEqual(['http://sub.example.com/x']);
	});

	test('rejects data: / file: / ftp: schemes', () => {
		for (const line of ['data:text/plain,hi', 'file:///etc/passwd', 'ftp://example.com/x']) {
			const r = classifySubInput(line);
			expect(r.fetchUrls).toEqual([]);
			expect(r.skipped).toEqual([line]);
		}
	});

	test('rejects private / loopback / metadata IP tens', () => {
		for (const host of [
			'http://169.254.169.254/latest/meta-data/',
			'http://127.0.0.1:6379/',
			'http://10.1.2.3/',
			'http://192.168.1.1/',
			'http://172.16.0.1/',
			'http://[::1]/'
		]) {
			const r = classifySubInput(host);
			expect(r.fetchUrls).toEqual([]);
			expect(r.skipped).toEqual([host]);
		}
	});

	test('allows public IP and normal domains', () => {
		for (const line of ['http://203.0.113.7/sub', 'https://sub.example.com/link']) {
			const r = classifySubInput(line);
			expect(r.fetchUrls).toEqual([line]);
		}
	});

	test('classifies proxy lines locally', () => {
		const r = classifySubInput('vless://11111111-1111-1111-1111-111111111111@example.com:443?type=tcp&security=none');
		expect(r.fetchUrls).toEqual([]);
		expect(r.proxyLines.length).toBe(1);
	});

	test('truncates fetchUrls to 20', () => {
		const lines = Array.from({ length: 25 }, (_, i) => `https://sub${i}.example.com/x`);
		const r = classifySubInput(lines.join('\n'));
		expect(r.fetchUrls.length).toBe(20);
	});

	test('flags input over 50KB as tooLarge', () => {
		const big = 'a'.repeat(50_001);
		const r = classifySubInput(big);
		expect(r.tooLarge).toBe(true);
	});
});

describe('logSafeUrl', () => {
	test('strips userinfo and hash', () => {
		const safe = logSafeUrl('https://user:pass@sub.example.com/link#fragment');
		expect(safe).not.toContain('user');
		expect(safe).not.toContain('pass');
		expect(safe).not.toContain('#fragment');
	});

	test('truncates over-long URLs to 200 chars', () => {
		const long = 'https://sub.example.com/' + 'a'.repeat(500);
		const safe = logSafeUrl(long);
		expect(safe.length).toBeLessThanOrEqual(200);
	});
});
