import http from 'http';
import https from 'https';
import urllib from 'url';
import zlib from 'zlib';
import { PassThrough } from 'stream';

import Cookies from './cookies';
import packageData from '../../package.json';

const MAX_REDIRECTS = 5;

function fetch(url, options) {
    options = options || {};

    options.fetchRes = options.fetchRes || new PassThrough();
    options.cookies = options.cookies || new Cookies({});
    options.redirects = options.redirects || 0;
    options.maxRedirects = isNaN(options.maxRedirects)
        ? MAX_REDIRECTS
        : options.maxRedirects;

    if (options.cookie) {
        [].concat(options.cookie || []).forEach((cookie) => {
            options.cookies.set(cookie, url);
        });
        options.cookie = false;
    }

    const fetchRes = options.fetchRes;
    const parsed = urllib.parse(url);
    let method =
        (options.method || '').toString().trim().toUpperCase() || 'GET';
    let finished = false;
    let cookies;
    let body;

    const handler = parsed.protocol === 'https:' ? https : http;

    const headers: any = {
        'accept-encoding': 'gzip,deflate',
        'user-agent': 'nodemailer/' + packageData.version,
    };

    Object.keys(options.headers || {}).forEach((key) => {
        headers[key.toLowerCase().trim()] = options.headers[key];
    });

    if (options.userAgent) {
        headers['user-agent'] = options.userAgent;
    }

    if (parsed.auth) {
        headers.Authorization =
            'Basic ' + Buffer.from(parsed.auth).toString('base64');
    }

    if ((cookies = options.cookies.get(url))) {
        headers.cookie = cookies;
    }

    if (options.body) {
        if (options.contentType !== false) {
            headers['Content-Type'] =
                options.contentType || 'application/x-www-form-urlencoded';
        }

        if (typeof options.body.pipe === 'function') {
            // it's a stream
            headers['Transfer-Encoding'] = 'chunked';
            body = options.body;
            body.on('error', (err) => {
                if (finished) {
                    return;
                }
                finished = true;
                err.type = 'FETCH';
                err.sourceUrl = url;
                fetchRes.emit('error', err);
            });
        } else {
            if (options.body instanceof Buffer) {
                body = options.body;
            } else if (typeof options.body === 'object') {
                try {
                    // encodeURIComponent can fail on invalid input (partial emoji etc.)
                    body = Buffer.from(
                        Object.keys(options.body)
                            .map((key) => {
                                const value = options.body[key]
                                    .toString()
                                    .trim();
                                return (
                                    encodeURIComponent(key) +
                                    '=' +
                                    encodeURIComponent(value)
                                );
                            })
                            .join('&')
                    );
                } catch (E) {
                    if (finished) {
                        return;
                    }
                    finished = true;
                    E.type = 'FETCH';
                    E.sourceUrl = url;
                    fetchRes.emit('error', E);
                    return;
                }
            } else {
                body = Buffer.from(options.body.toString().trim());
            }

            headers['Content-Type'] =
                options.contentType || 'application/x-www-form-urlencoded';
            headers['Content-Length'] = body.length;
        }
        // if method is not provided, use POST instead of GET
        method =
            (options.method || '').toString().trim().toUpperCase() || 'POST';
    }

    let req;
    const reqOptions = {
        method,
        host: parsed.hostname,
        path: parsed.path,
        port: parsed.port
            ? parsed.port
            : parsed.protocol === 'https:'
            ? 443
            : 80,
        headers,
        rejectUnauthorized: false,
        agent: false,
    };

    if (options.tls) {
        Object.keys(options.tls).forEach((key) => {
            reqOptions[key] = options.tls[key];
        });
    }

    try {
        req = handler.request(reqOptions);
    } catch (E) {
        finished = true;
        setImmediate(() => {
            E.type = 'FETCH';
            E.sourceUrl = url;
            fetchRes.emit('error', E);
        });
        return fetchRes;
    }

    if (options.timeout) {
        req.setTimeout(options.timeout, () => {
            if (finished) {
                return;
            }
            finished = true;
            req.abort();
            const err: any = new Error('Request Timeout');
            err.type = 'FETCH';
            err.sourceUrl = url;
            fetchRes.emit('error', err);
        });
    }

    req.on('error', (err) => {
        if (finished) {
            return;
        }
        finished = true;
        err.type = 'FETCH';
        err.sourceUrl = url;
        fetchRes.emit('error', err);
    });

    req.on('response', (res) => {
        let inflate;

        if (finished) {
            return;
        }

        switch (res.headers['content-encoding']) {
            case 'gzip':
            case 'deflate':
                inflate = zlib.createUnzip();
                break;
        }

        if (res.headers['set-cookie']) {
            [].concat(res.headers['set-cookie'] || []).forEach((cookie) => {
                options.cookies.set(cookie, url);
            });
        }

        if (
            [301, 302, 303, 307, 308].includes(res.statusCode) &&
            res.headers.location
        ) {
            // redirect
            options.redirects++;
            if (options.redirects > options.maxRedirects) {
                finished = true;
                const err: any = new Error('Maximum redirect count exceeded');
                err.type = 'FETCH';
                err.sourceUrl = url;
                fetchRes.emit('error', err);
                req.abort();
                return;
            }
            // redirect does not include POST body
            options.method = 'GET';
            options.body = false;
            return fetch(urllib.resolve(url, res.headers.location), options);
        }

        fetchRes.statusCode = res.statusCode;
        fetchRes.headers = res.headers;

        if (res.statusCode >= 300 && !options.allowErrorResponse) {
            finished = true;
            const err: any = new Error('Invalid status code ' + res.statusCode);
            err.type = 'FETCH';
            err.sourceUrl = url;
            fetchRes.emit('error', err);
            req.abort();
            return;
        }

        res.on('error', (err) => {
            if (finished) {
                return;
            }
            finished = true;
            err.type = 'FETCH';
            err.sourceUrl = url;
            fetchRes.emit('error', err);
            req.abort();
        });

        if (inflate) {
            res.pipe(inflate).pipe(fetchRes);
            inflate.on('error', (err) => {
                if (finished) {
                    return;
                }
                finished = true;
                err.type = 'FETCH';
                err.sourceUrl = url;
                fetchRes.emit('error', err);
                req.abort();
            });
        } else {
            res.pipe(fetchRes);
        }
    });

    setImmediate(() => {
        if (body) {
            try {
                if (typeof body.pipe === 'function') {
                    return body.pipe(req);
                } else {
                    req.write(body);
                }
            } catch (err) {
                finished = true;
                err.type = 'FETCH';
                err.sourceUrl = url;
                fetchRes.emit('error', err);
                return;
            }
        }
        req.end();
    });

    return fetchRes;
}

export { Cookies };

export default function (url, options?) {
    return fetch(url, options);
}
