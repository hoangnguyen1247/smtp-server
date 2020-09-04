"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports["default"] = _default;
Object.defineProperty(exports, "Cookies", {
  enumerable: true,
  get: function get() {
    return _cookies["default"];
  }
});

var _typeof2 = _interopRequireDefault(require("@babel/runtime/helpers/typeof"));

var _http = _interopRequireDefault(require("http"));

var _https = _interopRequireDefault(require("https"));

var _url = _interopRequireDefault(require("url"));

var _zlib = _interopRequireDefault(require("zlib"));

var _stream = require("stream");

var _cookies = _interopRequireDefault(require("./cookies"));

var _package = _interopRequireDefault(require("../../package.json"));

var MAX_REDIRECTS = 5;

function fetch(url, options) {
  options = options || {};
  options.fetchRes = options.fetchRes || new _stream.PassThrough();
  options.cookies = options.cookies || new _cookies["default"]({});
  options.redirects = options.redirects || 0;
  options.maxRedirects = isNaN(options.maxRedirects) ? MAX_REDIRECTS : options.maxRedirects;

  if (options.cookie) {
    [].concat(options.cookie || []).forEach(function (cookie) {
      options.cookies.set(cookie, url);
    });
    options.cookie = false;
  }

  var fetchRes = options.fetchRes;

  var parsed = _url["default"].parse(url);

  var method = (options.method || '').toString().trim().toUpperCase() || 'GET';
  var finished = false;
  var cookies;
  var body;
  var handler = parsed.protocol === 'https:' ? _https["default"] : _http["default"];
  var headers = {
    'accept-encoding': 'gzip,deflate',
    'user-agent': 'nodemailer/' + _package["default"].version
  };
  Object.keys(options.headers || {}).forEach(function (key) {
    headers[key.toLowerCase().trim()] = options.headers[key];
  });

  if (options.userAgent) {
    headers['user-agent'] = options.userAgent;
  }

  if (parsed.auth) {
    headers.Authorization = 'Basic ' + Buffer.from(parsed.auth).toString('base64');
  }

  if (cookies = options.cookies.get(url)) {
    headers.cookie = cookies;
  }

  if (options.body) {
    if (options.contentType !== false) {
      headers['Content-Type'] = options.contentType || 'application/x-www-form-urlencoded';
    }

    if (typeof options.body.pipe === 'function') {
      // it's a stream
      headers['Transfer-Encoding'] = 'chunked';
      body = options.body;
      body.on('error', function (err) {
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
      } else if ((0, _typeof2["default"])(options.body) === 'object') {
        try {
          // encodeURIComponent can fail on invalid input (partial emoji etc.)
          body = Buffer.from(Object.keys(options.body).map(function (key) {
            var value = options.body[key].toString().trim();
            return encodeURIComponent(key) + '=' + encodeURIComponent(value);
          }).join('&'));
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

      headers['Content-Type'] = options.contentType || 'application/x-www-form-urlencoded';
      headers['Content-Length'] = body.length;
    } // if method is not provided, use POST instead of GET


    method = (options.method || '').toString().trim().toUpperCase() || 'POST';
  }

  var req;
  var reqOptions = {
    method: method,
    host: parsed.hostname,
    path: parsed.path,
    port: parsed.port ? parsed.port : parsed.protocol === 'https:' ? 443 : 80,
    headers: headers,
    rejectUnauthorized: false,
    agent: false
  };

  if (options.tls) {
    Object.keys(options.tls).forEach(function (key) {
      reqOptions[key] = options.tls[key];
    });
  }

  try {
    req = handler.request(reqOptions);
  } catch (E) {
    finished = true;
    setImmediate(function () {
      E.type = 'FETCH';
      E.sourceUrl = url;
      fetchRes.emit('error', E);
    });
    return fetchRes;
  }

  if (options.timeout) {
    req.setTimeout(options.timeout, function () {
      if (finished) {
        return;
      }

      finished = true;
      req.abort();
      var err = new Error('Request Timeout');
      err.type = 'FETCH';
      err.sourceUrl = url;
      fetchRes.emit('error', err);
    });
  }

  req.on('error', function (err) {
    if (finished) {
      return;
    }

    finished = true;
    err.type = 'FETCH';
    err.sourceUrl = url;
    fetchRes.emit('error', err);
  });
  req.on('response', function (res) {
    var inflate;

    if (finished) {
      return;
    }

    switch (res.headers['content-encoding']) {
      case 'gzip':
      case 'deflate':
        inflate = _zlib["default"].createUnzip();
        break;
    }

    if (res.headers['set-cookie']) {
      [].concat(res.headers['set-cookie'] || []).forEach(function (cookie) {
        options.cookies.set(cookie, url);
      });
    }

    if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
      // redirect
      options.redirects++;

      if (options.redirects > options.maxRedirects) {
        finished = true;
        var err = new Error('Maximum redirect count exceeded');
        err.type = 'FETCH';
        err.sourceUrl = url;
        fetchRes.emit('error', err);
        req.abort();
        return;
      } // redirect does not include POST body


      options.method = 'GET';
      options.body = false;
      return fetch(_url["default"].resolve(url, res.headers.location), options);
    }

    fetchRes.statusCode = res.statusCode;
    fetchRes.headers = res.headers;

    if (res.statusCode >= 300 && !options.allowErrorResponse) {
      finished = true;

      var _err = new Error('Invalid status code ' + res.statusCode);

      _err.type = 'FETCH';
      _err.sourceUrl = url;
      fetchRes.emit('error', _err);
      req.abort();
      return;
    }

    res.on('error', function (err) {
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
      inflate.on('error', function (err) {
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
  setImmediate(function () {
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

function _default(url, options) {
  return fetch(url, options);
}