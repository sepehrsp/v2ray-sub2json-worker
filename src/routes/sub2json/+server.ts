// src/routes/Sub2JSON/+server.ts
import type { RequestHandler } from '@sveltejs/kit';
import { convert } from '$lib/utils/conversion';
import { classifySubInput, logSafeUrl, isBase64 } from '$lib/utils/helpers';

const jsonHeaders = {
	'Content-Type': 'application/json',
	'Cache-Control': 'no-store',
	'X-Content-Type-Options': 'nosniff'
};

const FETCH_TIMEOUT_MS = 10_000;

export const GET: RequestHandler = async ({ url }) => {
	const sub = url.searchParams.get('sub') || 'https://example.com/sub';
	const limit = url.searchParams.get('limit')?.split(',');

	const classified = classifySubInput(sub);
	if (classified.tooLarge) {
		return new Response(JSON.stringify({ error: 'Input too large' }), {
			status: 413,
			headers: jsonHeaders
		});
	}

	const { proxyLines, fetchUrls } = classified;
	for (const line of classified.skipped) {
		console.log(`Skipping invalid line: ${logSafeUrl(line)}`);
	}

	// Fetch all subscription URLs concurrently so wall time is the slowest fetch,
	// not the sum of all fetches.
	const results = await Promise.allSettled(
		fetchUrls.map(async (line) => {
			try {
				const response = await fetch(line, { signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
				if (!response.ok) {
					console.error(`Fetch failed for ${logSafeUrl(line)}: ${response.status}`);
					return '';
				}
				const responseText = await response.text();
				// Only attempt base64 decode for reasonably-sized single-line bodies.
				if (responseText.length < 1_000_000 && !/\s/.test(responseText) && isBase64(responseText)) {
					return atob(responseText);
				}
				return responseText;
			} catch (error) {
				console.error(`Fetch error for ${logSafeUrl(line)}:`, error instanceof Error ? error.message : String(error));
				return '';
			}
		})
	);

	const fetched = results
		.filter((r): r is PromiseFulfilledResult<string> => r.status === 'fulfilled')
		.map((r) => r.value)
		.join('\n');

	const data = [...proxyLines, fetched].filter(Boolean).join('\n');

	try {
		const result = await convert(data, limit);
		return new Response(JSON.stringify(result, null, 2), {
			status: 200,
			headers: jsonHeaders
		});
	} catch (error: unknown) {
		const errorMessage = error instanceof Error ? error.message : String(error);
		console.error('Conversion error:', errorMessage);
		return new Response(JSON.stringify({ error: 'Conversion failed' }), {
			status: 500,
			headers: jsonHeaders
		});
	}
};