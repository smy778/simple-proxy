import { getBodyBuffer } from '@/utils/body';
import {
    getProxyHeaders,
    getAfterResponseHeaders,
    getBlacklistedHeaders,
} from '@/utils/headers';
import {
    createTokenIfNeeded,
    isAllowedToMakeRequest,
    setTokenHeader,
} from '@/utils/turnstile';

const DEFAULT_USER_AGENT =
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36';

function toHeaderValue(value: string | string[] | undefined) {
    if (value == null) return undefined;
    return Array.isArray(value) ? value.join(', ') : String(value);
}

function normalizeForcedHeaders(input: unknown) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        return {};
    }

    return Object.fromEntries(
        Object.entries(input)
            .filter(([, value]) => value != null)
            .map(([key, value]) => [String(key).toLowerCase(), String(value)]),
    ) as Record<string, string>;
}

function getProxyResponseType(
    headers: Record<string, string | string[] | undefined>,
) {
    return toHeaderValue(headers['x-proxy-response-type'])?.trim().toLowerCase();
}

function getForcedHeadersFromIncoming(
    headers: Record<string, string | string[] | undefined>,
) {
    const out: Record<string, string> = {};

    for (const [rawKey, rawValue] of Object.entries(headers || {})) {
        const key = rawKey.toLowerCase();
        const value = toHeaderValue(rawValue);

        if (!key.startsWith('x-')) continue;
        if (key.startsWith('x-proxy-')) continue;
        if (value == null) continue;

        out[key.slice(2)] = value;
    }

    return out;
}

export default defineEventHandler(async (event) => {
    if (isPreflightRequest(event)) {
        handleCors(event, {});
        event.node.res.statusCode = 204;
        event.node.res.end();
        return;
    }

    if (event.node.req.method === 'OPTIONS') {
        throw createError({
            statusCode: 405,
            statusMessage: 'Method Not Allowed',
        });
    }

    const query = getQuery<{
        destination?: string;
        headers?: string;
    }>(event);

    const destination = query.destination;
    if (!destination) {
        return await sendJson({
            event,
            status: 200,
            data: {
                message: `Proxy is working as expected (v${
                    useRuntimeConfig(event).version
                })`,
            },
        });
    }

    if (!(await isAllowedToMakeRequest(event))) {
        return await sendJson({
            event,
            status: 401,
            data: {
                error: 'Invalid or missing token',
            },
        });
    }

    const method = (event.node.req.method || 'GET').toUpperCase();
    const body = await getBodyBuffer(event);
    const token = await createTokenIfNeeded(event);
    const proxyResponseType = getProxyResponseType(event.node.req.headers);

    let queryForcedHeaders: Record<string, string> = {};
    if (query.headers) {
        try {
            queryForcedHeaders = normalizeForcedHeaders(JSON.parse(query.headers));
        } catch {
            throw createError({
                statusCode: 400,
                statusMessage: 'Invalid headers query parameter',
            });
        }
    }

    const proxyHeaders = new Headers(
        getProxyHeaders(event.headers) as HeadersInit,
    );

    proxyHeaders.delete('origin');
    proxyHeaders.delete('referer');

    for (const rawKey of Object.keys(event.node.req.headers || {})) {
        const key = rawKey.toLowerCase();
        if (key.startsWith('x-')) {
            proxyHeaders.delete(key);
        }
    }

    const incomingForcedHeaders = getForcedHeadersFromIncoming(
        event.node.req.headers,
    );

    for (const [key, value] of Object.entries(incomingForcedHeaders)) {
        proxyHeaders.set(key, value);
    }

    for (const [key, value] of Object.entries(queryForcedHeaders)) {
        proxyHeaders.set(key, value);
    }

    if (!proxyHeaders.get('user-agent')?.trim()) {
        proxyHeaders.set('user-agent', DEFAULT_USER_AGENT);
    }

    const fetchOptions: RequestInit = {
        method,
        redirect: 'follow',
        headers: proxyHeaders,
    };

    if (method !== 'GET' && method !== 'HEAD' && body && body.length > 0) {
        fetchOptions.body = body;
    }

    try {
        if (proxyResponseType === 'text' || proxyResponseType === 'plaintext') {
            const response = await fetch(destination, fetchOptions);
            const text = await response.text();

            handleCors(event, {});
            event.node.res.statusCode = response.status;

            const headers = getAfterResponseHeaders(
                response.headers,
                response.url,
            ) as Record<string, string>;

            const filteredHeaders = Object.fromEntries(
                Object.entries(headers).filter(([key]) => {
                    const lower = key.toLowerCase();
                    return (
                        lower !== 'content-type' &&
                        lower !== 'content-length' &&
                        lower !== 'content-encoding' &&
                        lower !== 'transfer-encoding'
                    );
                }),
            );

            setResponseHeaders(event, filteredHeaders);
            event.node.res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            event.node.res.setHeader('X-Content-Type-Options', 'nosniff');

            if (token) setTokenHeader(event, token);

            event.node.res.end(text);
            return;
        }

        await specificProxyRequest(event, destination, {
            blacklistedHeaders: getBlacklistedHeaders(),
            fetchOptions,
            onResponse(outputEvent, response) {
                const headers = getAfterResponseHeaders(
                    response.headers,
                    response.url,
                );
                setResponseHeaders(outputEvent, headers);
                if (token) setTokenHeader(event, token);
            },
        });
    } catch (e) {
        console.log('Error fetching', e);
        throw e;
    }
});