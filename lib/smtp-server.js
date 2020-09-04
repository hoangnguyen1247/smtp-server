"use strict";

var _interopRequireWildcard = require("@babel/runtime/helpers/interopRequireWildcard");

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.SMTPServer = void 0;

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime/helpers/createClass"));

var _assertThisInitialized2 = _interopRequireDefault(require("@babel/runtime/helpers/assertThisInitialized"));

var _inherits2 = _interopRequireDefault(require("@babel/runtime/helpers/inherits"));

var _possibleConstructorReturn2 = _interopRequireDefault(require("@babel/runtime/helpers/possibleConstructorReturn"));

var _getPrototypeOf2 = _interopRequireDefault(require("@babel/runtime/helpers/getPrototypeOf"));

var _defineProperty2 = _interopRequireDefault(require("@babel/runtime/helpers/defineProperty"));

var _net = _interopRequireDefault(require("net"));

var _tls = _interopRequireDefault(require("tls"));

var _punycode = _interopRequireDefault(require("punycode"));

var _crypto = _interopRequireDefault(require("crypto"));

var _base = _interopRequireDefault(require("base32.js"));

var _events = _interopRequireDefault(require("events"));

var shared = _interopRequireWildcard(require("./shared"));

var _smtpConnection = require("./smtp-connection");

var _tlsOptions = _interopRequireDefault(require("./tls-options"));

function _createSuper(Derived) { var hasNativeReflectConstruct = _isNativeReflectConstruct(); return function _createSuperInternal() { var Super = (0, _getPrototypeOf2["default"])(Derived), result; if (hasNativeReflectConstruct) { var NewTarget = (0, _getPrototypeOf2["default"])(this).constructor; result = Reflect.construct(Super, arguments, NewTarget); } else { result = Super.apply(this, arguments); } return (0, _possibleConstructorReturn2["default"])(this, result); }; }

function _isNativeReflectConstruct() { if (typeof Reflect === "undefined" || !Reflect.construct) return false; if (Reflect.construct.sham) return false; if (typeof Proxy === "function") return true; try { Date.prototype.toString.call(Reflect.construct(Date, [], function () {})); return true; } catch (e) { return false; } }

var CLOSE_TIMEOUT = 30 * 1000; // how much to wait until pending connections are terminated

/**
 * Creates a SMTP server instance.
 *
 * @constructor
 * @param {Object} options Connection and SMTP optionsž
 */

var SMTPServer = /*#__PURE__*/function (_events$EventEmitter) {
  (0, _inherits2["default"])(SMTPServer, _events$EventEmitter);

  var _super = _createSuper(SMTPServer);

  function SMTPServer(options) {
    var _this;

    (0, _classCallCheck2["default"])(this, SMTPServer);
    _this = _super.call(this);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "options", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "logger", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_closeTimeout", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "connections", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "secureContext", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "server", void 0);
    _this.options = options || {};

    _this.updateSecureContext(); // setup disabled commands list


    _this.options.disabledCommands = [].concat(_this.options.disabledCommands || []).map(function (command) {
      return (command || '').toString().toUpperCase().trim();
    }); // setup allowed auth methods

    _this.options.authMethods = [].concat(_this.options.authMethods || []).map(function (method) {
      return (method || '').toString().toUpperCase().trim();
    });

    if (!_this.options.authMethods.length) {
      _this.options.authMethods = ['LOGIN', 'PLAIN'];
    }

    _this.logger = shared.getLogger(_this.options, {
      component: _this.options.component || 'smtp-server'
    }); // apply shorthand handlers

    ['onConnect', 'onAuth', 'onMailFrom', 'onRcptTo', 'onData', 'onClose'].forEach(function (handler) {
      if (typeof _this.options[handler] === 'function') {
        _this[handler] = _this.options[handler];
      }
    });
    /**
     * Timeout after close has been called until pending connections are forcibly closed
     */

    _this._closeTimeout = undefined;
    /**
     * A set of all currently open connections
     */

    _this.connections = new Set(); // setup server listener and connection handler

    if (_this.options.secure && !_this.options.needsUpgrade) {
      _this.server = _net["default"].createServer(_this.options, function (socket) {
        _this._handleProxy(socket, function (err, socketOptions) {
          if (err) {// ignore, should not happen
          }

          if (_this.options.secured) {
            return _this.connect(socket, socketOptions);
          }

          _this._upgrade(socket, function (err, tlsSocket) {
            if (err) {
              return _this._onError(err);
            }

            _this.connect(tlsSocket, socketOptions);
          });
        });
      });
    } else {
      _this.server = _net["default"].createServer(_this.options, function (socket) {
        return _this._handleProxy(socket, function (err, socketOptions) {
          if (err) {// ignore, should not happen
          }

          _this.connect(socket, socketOptions);
        });
      });
    }

    _this._setListeners();

    return _this;
  }

  (0, _createClass2["default"])(SMTPServer, [{
    key: "connect",
    value: function connect(socket, socketOptions) {
      var _this2 = this;

      var connection = new _smtpConnection.SMTPConnection(this, socket, socketOptions);
      this.connections.add(connection);
      connection.on('error', function (err) {
        return _this2._onError(err);
      });
      connection.on('connect', function (data) {
        return _this2._onClientConnect(data);
      });
      connection.init();
    }
    /**
     * Start listening on selected port and interface
     */

  }, {
    key: "listen",
    value: function listen() {
      var _this$server;

      return (_this$server = this.server).listen.apply(_this$server, arguments);
    }
    /**
     * Closes the server
     *
     * @param {Function} callback Callback to run once the server is fully closed
     */

  }, {
    key: "close",
    value: function close(callback) {
      var _this3 = this;

      var connections = this.connections.size;
      var timeout = this.options.closeTimeout || CLOSE_TIMEOUT; // stop accepting new connections

      this.server.close(function () {
        clearTimeout(_this3._closeTimeout);

        if (typeof callback === 'function') {
          return callback();
        }
      }); // close active connections

      if (connections) {
        this.logger.info({
          tnx: 'close'
        }, 'Server closing with %s pending connection%s, waiting %s seconds before terminating', connections, connections !== 1 ? 's' : '', timeout / 1000);
      }

      this._closeTimeout = setTimeout(function () {
        connections = _this3.connections.size;

        if (connections) {
          _this3.logger.info({
            tnx: 'close'
          }, 'Closing %s pending connection%s to close the server', connections, connections !== 1 ? 's' : '');

          _this3.connections.forEach(function (connection) {
            connection.send(421, 'Server shutting down');
            connection.close();
          });
        }

        if (typeof callback === 'function') {
          var realCallback = callback;
          callback = null;
          return realCallback();
        }
      }, timeout);
    }
    /**
     * Authentication handler. Override this
     *
     * @param {Object} auth Authentication options
     * @param {Function} callback Callback to run once the user is authenticated
     */

  }, {
    key: "onAuth",
    value: function onAuth(auth, session, callback) {
      if (auth.method === 'XOAUTH2') {
        return callback(null, {
          data: {
            status: '401',
            schemes: 'bearer mac',
            scope: 'https://mail.google.com/'
          }
        });
      }

      if (auth.method === 'XCLIENT') {
        return callback(); // pass through
      }

      return callback(null, {
        message: 'Authentication not implemented'
      });
    }
  }, {
    key: "onConnect",
    value: function onConnect(session, callback) {
      setImmediate(callback);
    }
  }, {
    key: "onMailFrom",
    value: function onMailFrom(address, session, callback) {
      setImmediate(callback);
    }
  }, {
    key: "onRcptTo",
    value: function onRcptTo(address, session, callback) {
      setImmediate(callback);
    }
  }, {
    key: "onData",
    value: function onData(stream, session, callback) {
      var _this4 = this;

      var chunklen = 0;
      stream.on('data', function (chunk) {
        chunklen += chunk.length;
      });
      stream.on('end', function () {
        _this4.logger.info({
          tnx: 'message',
          size: chunklen
        }, '<received %s bytes>', chunklen);

        callback();
      });
    }
  }, {
    key: "onClose",
    value: function onClose()
    /* session */
    {// do nothing
    }
  }, {
    key: "updateSecureContext",
    value: function updateSecureContext(options) {
      var _this5 = this;

      Object.keys(options || {}).forEach(function (key) {
        _this5.options[key] = options[key];
      });
      var defaultTlsOptions = (0, _tlsOptions["default"])(this.options);
      this.secureContext = new Map();
      this.secureContext.set('*', _tls["default"].createSecureContext(defaultTlsOptions));
      var ctxMap = this.options.sniOptions || {}; // sniOptions is either an object or a Map with domain names as keys and TLS option objects as values

      if (typeof ctxMap.get === 'function') {
        ctxMap.forEach(function (ctx, servername) {
          _this5.secureContext.set(_this5._normalizeHostname(servername), _tls["default"].createSecureContext((0, _tlsOptions["default"])(ctx)));
        });
      } else {
        Object.keys(ctxMap).forEach(function (servername) {
          _this5.secureContext.set(_this5._normalizeHostname(servername), _tls["default"].createSecureContext((0, _tlsOptions["default"])(ctxMap[servername])));
        });
      }

      if (this.options.secure) {
        // appy changes
        Object.keys(defaultTlsOptions || {}).forEach(function (key) {
          if (!(key in _this5.options)) {
            _this5.options[key] = defaultTlsOptions[key];
          }
        }); // ensure SNICallback method

        if (typeof this.options.SNICallback !== 'function') {
          // create default SNI handler
          this.options.SNICallback = function (servername, cb) {
            cb(null, _this5.secureContext.get(_this5._normalizeHostname(servername)) || _this5.secureContext.get('*'));
          };
        }
      }
    } // PRIVATE METHODS

    /**
     * Setup server event handlers
     */

  }, {
    key: "_setListeners",
    value: function _setListeners() {
      var _this6 = this;

      var server = this.server;
      server.once('listening', function () {
        return _this6._onListening();
      });
      server.once('close', function () {
        return _this6._onClose(server);
      });
      server.on('error', function () {
        return _this6._onError.apply(_this6, arguments);
      });
    }
    /**
     * Called when server started listening
     *
     * @event
     */

  }, {
    key: "_onListening",
    value: function _onListening() {
      var address = this.server.address(); // address will be null if listener is using Unix socket

      if (address === null) {
        address = {
          address: null,
          port: null,
          family: null
        };
      }

      this.logger.info( //
      {
        tnx: 'listen',
        host: address.address,
        port: address.port,
        secure: !!this.options.secure,
        protocol: this.options.lmtp ? 'LMTP' : 'SMTP'
      }, '%s%s Server listening on %s:%s', this.options.secure ? 'Secure ' : '', this.options.lmtp ? 'LMTP' : 'SMTP', address.family === 'IPv4' ? address.address : '[' + address.address + ']', address.port);
    }
    /**
     * Called when server is closed
     *
     * @event
     */

  }, {
    key: "_onClose",
    value: function _onClose(server) {
      this.logger.info({
        tnx: 'closed'
      }, (this.options.lmtp ? 'LMTP' : 'SMTP') + ' Server closed');

      if (server !== this.server) {
        // older instance was closed
        return;
      }

      this.emit('close');
    }
    /**
     * Called when an error occurs with the server
     *
     * @event
     */

  }, {
    key: "_onError",
    value: function _onError(err) {
      this.emit('error', err);
    }
  }, {
    key: "_handleProxy",
    value: function _handleProxy(socket, callback) {
      var _this7 = this;

      var socketOptions = {
        id: _base["default"].encode(_crypto["default"].randomBytes(10)).toLowerCase()
      };

      if (!this.options.useProxy || Array.isArray(this.options.useProxy) && !this.options.useProxy.includes(socket.remoteAddress) && !this.options.useProxy.includes('*')) {
        socketOptions.ignore = this.options.ignoredHosts && this.options.ignoredHosts.includes(socket.remoteAddress);
        return setImmediate(function () {
          return callback(null, socketOptions);
        });
      }

      var chunks = [];
      var chunklen = 0;

      var socketReader = function socketReader() {
        var chunk;

        while ((chunk = socket.read()) !== null) {
          for (var i = 0, len = chunk.length; i < len; i++) {
            var chr = chunk[i];

            if (chr === 0x0a) {
              socket.removeListener('readable', socketReader);
              chunks.push(chunk.slice(0, i + 1));
              chunklen += i + 1;
              var remainder = chunk.slice(i + 1);

              if (remainder.length) {
                socket.unshift(remainder);
              }

              var header = Buffer.concat(chunks, chunklen).toString().trim();
              var params = (header || '').toString().split(' ');
              var commandName = params.shift().toUpperCase();

              if (commandName !== 'PROXY') {
                try {
                  socket.end('* BAD Invalid PROXY header\r\n');
                } catch (E) {// ignore
                }

                return;
              }

              if (params[1]) {
                socketOptions.remoteAddress = params[1].trim().toLowerCase();
                socketOptions.ignore = _this7.options.ignoredHosts && _this7.options.ignoredHosts.includes(socketOptions.remoteAddress);

                if (!socketOptions.ignore) {
                  _this7.logger.info({
                    tnx: 'proxy',
                    cid: socketOptions.id,
                    proxy: params[1].trim().toLowerCase()
                  }, '[%s] PROXY from %s through %s (%s)', socketOptions.id, params[1].trim().toLowerCase(), params[2].trim().toLowerCase(), JSON.stringify(params));
                }

                if (params[3]) {
                  socketOptions.remotePort = Number(params[3].trim()) || socketOptions.remotePort;
                }
              }

              return callback(null, socketOptions);
            }
          }

          chunks.push(chunk);
          chunklen += chunk.length;
        }
      };

      socket.on('readable', socketReader);
    }
    /**
     * Called when a new connection is established. This might not be the same time the socket is opened
     *
     * @event
     */

  }, {
    key: "_onClientConnect",
    value: function _onClientConnect(data) {
      this.emit('connect', data);
    }
    /**
     * Normalize hostname
     *
     * @event
     */

  }, {
    key: "_normalizeHostname",
    value: function _normalizeHostname(hostname) {
      try {
        hostname = _punycode["default"].toUnicode((hostname || '').toString().trim()).toLowerCase();
      } catch (E) {
        this.logger.error({
          tnx: 'punycode'
        }, 'Failed to process punycode domain "%s". error=%s', hostname, E.message);
      }

      return hostname;
    }
  }, {
    key: "_upgrade",
    value: function _upgrade(socket, callback) {
      var socketOptions = {
        secureContext: this.secureContext.get('*'),
        isServer: true,
        server: this.server,
        SNICallback: this.options.SNICallback
      };
      var returned = false;

      var onError = function onError(err) {
        if (returned) {
          return;
        }

        returned = true;
        callback(err || new Error('Socket closed unexpectedly'));
      }; // remove all listeners from the original socket besides the error handler


      socket.once('error', onError); // upgrade connection

      var tlsSocket = new _tls["default"].TLSSocket(socket, socketOptions);
      tlsSocket.once('close', onError);
      tlsSocket.once('error', onError);
      tlsSocket.once('_tlsError', onError);
      tlsSocket.once('clientError', onError);
      tlsSocket.once('tlsClientError', onError);
      tlsSocket.on('secure', function () {
        socket.removeListener('error', onError);
        tlsSocket.removeListener('close', onError);
        tlsSocket.removeListener('error', onError);
        tlsSocket.removeListener('_tlsError', onError);
        tlsSocket.removeListener('clientError', onError);
        tlsSocket.removeListener('tlsClientError', onError);

        if (returned) {
          try {
            tlsSocket.end();
          } catch (E) {//
          }

          return;
        }

        returned = true;
        return callback(null, tlsSocket);
      });
    }
  }]);
  return SMTPServer;
}(_events["default"].EventEmitter);

exports.SMTPServer = SMTPServer;