// src/lib/utils/helpers.ts
export function isValidUri(uri: string, isProxy = false, protocol = 'none'): boolean {
	try {
		new URL(uri);
		let protocolMatch = true;
		if (protocol !== 'none') protocolMatch = uri.startsWith(protocol + '://');
		if (isProxy) {
			const isVless = uri.startsWith('vless://');
			const isVmess = uri.startsWith('vmess://');
			const isTrojan = uri.startsWith('trojan://');
			const isShadowsocks = uri.startsWith('ss://');
			const isWireguard = uri.startsWith('wireguard://');
			return (isVless || isVmess || isTrojan || isShadowsocks || isWireguard) && protocolMatch;
		}
		return protocolMatch;
	} catch (e) {
		return false;
	}
}

export function decodeBase64(str: string): string {
	const base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
	let result = '';

	// Clean the string: remove anything not in the base64 alphabet or padding
	const cleanStr = str.replace(/[^A-Za-z0-9+/=]/g, '');

	// Pad to a multiple of 4 if needed
	const paddingNeeded = (4 - (cleanStr.length % 4)) % 4;
	const paddedStr = cleanStr + '='.repeat(paddingNeeded);

	// Manual decoding
	let buffer = 0,
		bits = 0;
	for (let i = 0; i < paddedStr.length; i++) {
		if (paddedStr[i] === '=') break; // Stop at padding
		const value = base64Chars.indexOf(paddedStr[i]);
		if (value === -1) continue; // Skip any remaining invalid chars

		buffer = (buffer << 6) + value;
		bits += 6;

		if (bits >= 8) {
			bits -= 8;
			const byte = (buffer >> bits) & 0xff;
			result += String.fromCharCode(byte);
		}
	}

	return result;
}

// Helper to build settings
export function buildSettings(params: {
	protocol: any;
	uid: any;
	password: any;
	address: any;
	port: any;
	flow: any;
	method: any;
	publicKey: any;
	endpoint: any;
	secretKey?: any;
}) {
	//const { address, protocol, password, method, security, sni, fp, host, path, headertype, serviceName, alpn, pbk, sid, spx } = params;
	const { protocol, uid, password, address, port, flow, method, publicKey, endpoint } = params;
	const { secretKey } = params;
	let settings = {};

	if (protocol === 'trojan') {
		settings = {
			servers: [
				{
					address,
					port,
					password
				}
			]
		};
	} else if (protocol === 'shadowsocks') {
		settings = {
			servers: [
				{
					address,
					port,
					method,
					password,
					uot: true,
					UoTVersion: 2
				}
			]
		};
	} else if (protocol === 'wireguard') {
		settings = {
			secretKey: secretKey || password,
			address,
			peers: [
				{
					publicKey,
					allowedIPs: ['0.0.0.0/0', '::/0'],
					endpoint
				}
			],
			mtu: 1280
		};
	} else {
		settings = {
			vnext: [
				{
					address,
					port,
					users: [
						{
							id: uid,
							alterId: 0,
							email: 't@t.tt',
							security: 'auto',
							encryption: protocol === 'vless' ? 'none' : undefined,
							flow: typeof flow === 'string' && flow.startsWith('xtls') ? flow : ''
						}
					]
				}
			]
		};
	}
	return settings;
}

// Helper to build stream settings
export function buildStreamSettings(params: {
	type: any;
	security: any;
	sni: any;
	fp: any;
	host: any;
	path: any;
	headertype: any;
	serviceName: any;
	alpn: any;
	pbk: any;
	sid: any;
	spx: any;
}) {
	const {
		type,
		security,
		sni,
		fp,
		host,
		path,
		headertype,
		serviceName,
		alpn,
		pbk,
		sid,
		spx
	} = params;
	const streamSettings: any = { network: type == '' ? 'tcp' : type };

	if (host && (type === 'tcp' || type === 'http')) {
		streamSettings.tcpSettings = {
			header: {
				type: headertype,
				request: {
					version: '1.1',
					method: 'GET',
					path: [path],
					headers: {
						Host: [host],
						'User-Agent': [''],
						'Accept-Encoding': ['gzip, deflate'],
						Connection: ['keep-alive'],
						Pragma: 'no-cache'
					}
				}
			}
		};
	}

	if (type === 'ws') {
		streamSettings.wsSettings = {
			path,
			headers: host ? { Host: host } : {}
		};
	}

	if (type === 'httpupgrade') {
		streamSettings.httpupgradeSettings = {
			path,
			host: host || undefined
		};
	}

	if (type === 'grpc') {
		streamSettings.grpcSettings = {
			serviceName: serviceName || '',
			multiMode: false,
			idle_timeout: 60,
			health_check_timeout: 20,
			permit_without_stream: false,
			initial_windows_size: 0
		};
	}

	if (security.startsWith('tls')) {
		streamSettings.security = 'tls';
		streamSettings.tlsSettings = {
			allowInsecure: true,
			serverName: sni,
			alpn: alpn.length ? alpn : [],
			show: false
		};
		if (fp && fp !== 'none') streamSettings.tlsSettings.fingerprint = fp;
	} else if (security.startsWith('reality')) {
		streamSettings.security = 'reality';
		streamSettings.realitySettings = {
			serverName: sni,
			fingerprint: fp,
			show: false,
			publicKey: pbk,
			shortId: sid || '',
			spiderX: spx || ''
		};
	} else {
		streamSettings.security = 'none';
	}
	return streamSettings;
}

// Helper to decode VMess URI
export function decodeVmessUri(uri: string) {
	const encoded = uri.split('://')[1];
	return JSON.parse(decodeBase64(encoded));
}

// Helper to parse URI parameters efficiently
export function parseUriParams(uri: string | URL) {
	const url = new URL(uri);
	const params = new URLSearchParams(url.search);
	const getParam = (key: string, defaultValue = '') => params.get(key) || defaultValue;
	const protocol = url.protocol.slice(0, -1);
	const port = parseInt(url.port, 10);
	const password =
		protocol === 'shadowsocks'
			? decodeURIComponent(url.password)
			: decodeURIComponent(url.username);

	return {
		protocol,
		uid: url.username || url.pathname.split('@')[0],
		password,
		method: protocol === 'shadowsocks' ? url.username : 'chacha20',
		address: protocol === 'wireguard' ? [getParam('address')] : url.hostname,
		endpoint: url.hostname + ':' + port,
		port,
		type: getParam('type'),
		security: getParam('security'),
		sni: getParam('sni'),
		fp: getParam('fp'),
		pbk: getParam('pbk'),
		sid: getParam('sid'),
		spx: getParam('spx'),
		flow: getParam('flow'),
		host: getParam('host'),
		path: getParam('path', '/'),
		headertype: getParam('headertype', 'http'),
		serviceName: getParam('serviceName'),
		alpn: getParam('alpn', '').split(',').filter(Boolean),
		publicKey: getParam('publickey'),
		secretKey: getParam('secretkey')
	};
}

// Helper to generate inbound configuration
export function generateInbounds(host = '127.0.0.1', port = 10809, socksport = 10808) {
	const sniffing = { enabled: true, destOverride: ['http', 'tls'], routeOnly: false };
	const settings = { auth: 'noauth', udp: true, allowTransparent: false };
	return {
		inbounds: [
			{ tag: 'socks', port: socksport, listen: host, protocol: 'socks', sniffing, settings },
			{ tag: 'http', port, listen: host, protocol: 'http', sniffing, settings }
		]
	};
}

export function isValidShadowsocksUrl4XRAY(uri: string) {
	try {
		if (typeof uri !== 'string') return false;
		uri = uri.trim();
		if (!uri) return false;
		if (!uri.startsWith('ss://')) return false;
		const protocolCount = (uri.match(/:\/\//g) || []).length;
		if (protocolCount > 1) return false;
		const [_, rest] = uri.split('ss://');
		if (!rest) return false;
		const [authHost] = rest.split('#');
		if (!authHost.includes('@')) return false;
		const [auth, hostPort] = authHost.split('@');
		if (!auth || !hostPort) return false;
		let method, password;
		if (isBase64(auth)) {
			const decoded = decodeBase64(auth);
			if (!decoded.includes(':')) return false;
			[method, password] = decoded.split(':');
		} else {
			if (!auth.includes(':')) return false;
			[method, password] = auth.split(':');
		}
		if (!method || !password) return false;

		// Supported Shadowsocks methods in Xray
		const supportedMethodsByXRAY = [
			'aes-128-gcm',
			'aes-256-gcm',
			'chacha20-ietf-poly1305',
			'xchacha20-ietf-poly1305',
			'none',
			'2022-blake3-aes-128-gcm',
			'2022-blake3-aes-256-gcm',
			'2022-blake3-chacha20-poly1305'
		];

		if (!supportedMethodsByXRAY.includes(method)) {
			return false;
		}
		const [host, port] = hostPort.split(':');
		if (!host || !port) return false;

		const portNum = parseInt(port, 10);
		if (isNaN(portNum) || portNum < 1 || portNum > 65535) return false;
		return true;
	} catch (e) {
		return false;
	}
}

export function isBase64(str: string) {
	if (typeof str !== 'string') return false;
	str = str.trim();
	if (!str) return false;

	// Pad the string if needed
	const paddingNeeded = (4 - (str.length % 4)) % 4;
	const paddedStr = str + '='.repeat(paddingNeeded);

	// Check length (should now be multiple of 4)
	if (paddedStr.length % 4 !== 0) return false;

	// Validate characters
	const base64Regex = /^[A-Za-z0-9+/=]+$/;
	if (!base64Regex.test(paddedStr)) return false;

	// Try decoding
	try {
		atob(paddedStr);
		return true;
	} catch (e) {
		return false;
	}
}

// Sanitize a URL for logging: strip userinfo and hash, truncate to 200 chars.
export function logSafeUrl(u: string): string {
	try {
		const x = new URL(u);
		x.username = '';
		x.password = '';
		x.hash = '';
		return x.toString().slice(0, 200);
	} catch {
		return u.slice(0, 200);
	}
}

// Private / loopback / link-local / reserved IP ranges that must not be fetched.
const PRIVATE_IP_PREFIXES = ['10.', '127.', '169.254.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '192.168.', '0.', '::1', '::', 'fc', 'fd', 'fe80'];

// Returns true when the hostname is an IP literal in a private/loopback range.
export function isPrivateOrLoopbackHost(hostname: string): boolean {
	const host = hostname.startsWith('[') ? hostname.slice(1, hostname.indexOf(']')) : hostname;
	return PRIVATE_IP_PREFIXES.some((p) => host.startsWith(p));
}

const MAX_FETCH_URLS = 20;
const MAX_SUB_LENGTH = 50_000;

export interface ClassifiedSubInput {
	proxyLines: string[];
	fetchUrls: string[];
	skipped: string[];
	tooLarge: boolean;
}

// Classify subscription input into local proxy lines and remote subscription
// URLs, applying scheme + private-IP guards. Pure: no I/O, no fetch.
export function classifySubInput(sub: string): ClassifiedSubInput {
	if (sub.length > MAX_SUB_LENGTH) return { proxyLines: [], fetchUrls: [], skipped: [], tooLarge: true };

	const proxyLines: string[] = [];
	const fetchUrls: string[] = [];
	const skipped: string[] = [];

	const lines = sub.split(/\r\n|\n|\r/).filter((line) => line.trim());

	for (const line of lines) {
		if (isValidUri(line, true)) {
			proxyLines.push(line);
			continue;
		}
		let parsed: URL;
		try {
			parsed = new URL(line);
		} catch {
			skipped.push(line);
			continue;
		}
		const protocol = parsed.protocol;
		if (protocol === 'https:' || protocol === 'http:') {
			if (isPrivateOrLoopbackHost(parsed.hostname)) {
				skipped.push(line);
			} else {
				fetchUrls.push(line);
			}
		} else {
			skipped.push(line);
		}
	}

	if (fetchUrls.length > MAX_FETCH_URLS) fetchUrls.length = MAX_FETCH_URLS;
	return { proxyLines, fetchUrls, skipped, tooLarge: false };
}
