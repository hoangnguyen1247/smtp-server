"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.SMTPConnection = void 0;

var _typeof2 = _interopRequireDefault(require("@babel/runtime/helpers/typeof"));

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime/helpers/createClass"));

var _assertThisInitialized2 = _interopRequireDefault(require("@babel/runtime/helpers/assertThisInitialized"));

var _inherits2 = _interopRequireDefault(require("@babel/runtime/helpers/inherits"));

var _possibleConstructorReturn2 = _interopRequireDefault(require("@babel/runtime/helpers/possibleConstructorReturn"));

var _getPrototypeOf2 = _interopRequireDefault(require("@babel/runtime/helpers/getPrototypeOf"));

var _defineProperty2 = _interopRequireDefault(require("@babel/runtime/helpers/defineProperty"));

var _dns = _interopRequireDefault(require("dns"));

var _tls = _interopRequireDefault(require("tls"));

var _net = _interopRequireDefault(require("net"));

var _ipv6Normalize = _interopRequireDefault(require("ipv6-normalize"));

var _crypto = _interopRequireDefault(require("crypto"));

var _os = _interopRequireDefault(require("os"));

var _punycode = _interopRequireDefault(require("punycode"));

var _events = _interopRequireDefault(require("events"));

var _base = _interopRequireDefault(require("base32.js"));

var _sasl = _interopRequireDefault(require("./sasl"));

var _smtpStream = require("./smtp-stream");

function _createSuper(Derived) { var hasNativeReflectConstruct = _isNativeReflectConstruct(); return function _createSuperInternal() { var Super = (0, _getPrototypeOf2["default"])(Derived), result; if (hasNativeReflectConstruct) { var NewTarget = (0, _getPrototypeOf2["default"])(this).constructor; result = Reflect.construct(Super, arguments, NewTarget); } else { result = Super.apply(this, arguments); } return (0, _possibleConstructorReturn2["default"])(this, result); }; }

function _isNativeReflectConstruct() { if (typeof Reflect === "undefined" || !Reflect.construct) return false; if (Reflect.construct.sham) return false; if (typeof Proxy === "function") return true; try { Date.prototype.toString.call(Reflect.construct(Date, [], function () {})); return true; } catch (e) { return false; } }

var SOCKET_TIMEOUT = 60 * 1000;
/**
 * Creates a handler for new socket
 *
 * @constructor
 * @param {Object} server Server instance
 * @param {Object} socket Socket instance
 */

var SMTPConnection = /*#__PURE__*/function (_events$EventEmitter) {
  (0, _inherits2["default"])(SMTPConnection, _events$EventEmitter);

  var _super = _createSuper(SMTPConnection);

  function SMTPConnection(server, socket, options) {
    var _this;

    (0, _classCallCheck2["default"])(this, SMTPConnection);
    _this = _super.call(this);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "id", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "ignore", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_server", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_socket", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "session", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_transactionCounter", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_ready", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_upgrading", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_nextHandler", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_parser", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_dataStream", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "secure", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "needsUpgrade", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "tlsOptions", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "localAddress", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "localPort", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "remoteAddress", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "remotePort", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_unauthenticatedCommands", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_maxAllowedUnauthenticatedCommands", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_unrecognizedCommands", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "name", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "clientHostname", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "openingCommand", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "hostNameAppearsAs", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_xClient", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_xForward", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_canEmitConnection", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_closing", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_closed", void 0);
    options = options || {}; // Random session ID, used for logging

    _this.id = options.id || _base["default"].encode(_crypto["default"].randomBytes(10)).toLowerCase();
    _this.ignore = options.ignore;
    _this._server = server;
    _this._socket = socket; // session data (envelope, user etc.)

    _this.session = _this.session = {
      id: _this.id
    }; // how many messages have been processed

    _this._transactionCounter = 0; // Do not allow input from client until initial greeting has been sent

    _this._ready = false; // If true then the connection is currently being upgraded to TLS

    _this._upgrading = false; // Set handler for incoming command and handler bypass detection by command name

    _this._nextHandler = undefined; // Parser instance for the incoming stream

    _this._parser = new _smtpStream.SMTPStream(); // Set handler for incoming commands

    _this._parser.oncommand = function () {
      var _this2;

      return (_this2 = _this)._onCommand.apply(_this2, arguments);
    }; // if currently in data mode, this stream gets the content of incoming message


    _this._dataStream = false; // If true, then the connection is using TLS

    _this.session.secure = _this.secure = !!_this._server.options.secure;
    _this.needsUpgrade = !!_this._server.options.needsUpgrade;
    _this.tlsOptions = _this.secure && !_this.needsUpgrade && _this._socket.getCipher ? _this._socket.getCipher() : false; // Store local and remote addresses for later usage

    _this.localAddress = (options.localAddress || _this._socket.localAddress || '').replace(/^::ffff:/, '');
    _this.localPort = Number(options.localPort || _this._socket.localPort) || 0;
    _this.remoteAddress = (options.remoteAddress || _this._socket.remoteAddress || '').replace(/^::ffff:/, '');
    _this.remotePort = Number(options.remotePort || _this._socket.remotePort) || 0; // normalize IPv6 addresses

    if (_this.localAddress && _net["default"].isIPv6(_this.localAddress)) {
      _this.localAddress = (0, _ipv6Normalize["default"])(_this.localAddress);
    }

    if (_this.remoteAddress && _net["default"].isIPv6(_this.remoteAddress)) {
      _this.remoteAddress = (0, _ipv6Normalize["default"])(_this.remoteAddress);
    } // Error counter - if too many commands in non-authenticated state are used, then disconnect


    _this._unauthenticatedCommands = 0; // Max allowed unauthenticated commands

    _this._maxAllowedUnauthenticatedCommands = _this._server.options.maxAllowedUnauthenticatedCommands || 10; // Error counter - if too many invalid commands are used, then disconnect

    _this._unrecognizedCommands = 0; // Server hostname for the greegins

    _this.name = _this._server.options.name || _os["default"].hostname(); // Resolved hostname for remote IP address

    _this.clientHostname = false; // The opening SMTP command (HELO, EHLO or LHLO)

    _this.openingCommand = false; // The hostname client identifies itself with

    _this.hostNameAppearsAs = false; // data passed from XCLIENT command

    _this._xClient = new Map(); // data passed from XFORWARD command

    _this._xForward = new Map(); // if true then can emit connection info

    _this._canEmitConnection = true; // increment connection count

    _this._closing = false;
    _this._closed = false;
    return _this;
  }
  /**
   * Initiates the connection. Checks connection limits and reverse resolves client hostname. The client
   * is not allowed to send anything before init has finished otherwise 'You talk too soon' error is returned
   */


  (0, _createClass2["default"])(SMTPConnection, [{
    key: "init",
    value: function init() {
      var _this3 = this;

      // Setup event handlers for the socket
      this._setListeners(function () {
        // Check that connection limit is not exceeded
        if (_this3._server.options.maxClients && _this3._server.connections.size > _this3._server.options.maxClients) {
          return _this3.send(421, _this3.name + ' Too many connected clients, try again in a moment');
        } // Keep a small delay for detecting early talkers


        setTimeout(function () {
          return _this3.connectionReady();
        }, 100);
      });
    }
  }, {
    key: "connectionReady",
    value: function connectionReady(next) {
      var _this4 = this;

      // Resolve hostname for the remote IP
      var reverseCb = function reverseCb(err, hostnames) {
        if (err) {
          _this4._server.logger.error({
            tnx: 'connection',
            cid: _this4.id,
            host: _this4.remoteAddress,
            hostname: _this4.clientHostname,
            err: err
          }, 'Reverse resolve for %s: %s', _this4.remoteAddress, err.message); // ignore resolve error

        }

        if (_this4._closing || _this4._closed) {
          return;
        }

        _this4.clientHostname = hostnames && hostnames.shift() || '[' + _this4.remoteAddress + ']';

        _this4._resetSession();

        _this4._server.onConnect(_this4.session, function (err) {
          _this4._server.logger.info({
            tnx: 'connection',
            cid: _this4.id,
            host: _this4.remoteAddress,
            hostname: _this4.clientHostname
          }, 'Connection from %s', _this4.clientHostname);

          if (err) {
            _this4.send(err.responseCode || 554, err.message);

            return _this4.close();
          }

          _this4._ready = true; // Start accepting data from input

          if (!_this4._server.options.useXClient && !_this4._server.options.useXForward) {
            _this4.emitConnection();
          }

          _this4.send(220, _this4.name + ' ' + (_this4._server.options.lmtp ? 'LMTP' : 'ESMTP') + (_this4._server.options.banner ? ' ' + _this4._server.options.banner : ''));

          if (typeof next === 'function') {
            next();
          }
        });
      }; // Skip reverse name resolution if disabled.


      if (this._server.options.disableReverseLookup) {
        return reverseCb(null, false);
      } // also make sure that we do not wait too long over the reverse resolve call


      var greetingSent = false;
      var reverseTimer = setTimeout(function () {
        clearTimeout(reverseTimer);

        if (greetingSent) {
          return;
        }

        greetingSent = true;
        reverseCb(new Error('Timeout'));
      }, 1500);

      try {
        // dns.reverse throws on invalid input, see https://github.com/nodejs/node/issues/3112
        _dns["default"].reverse(this.remoteAddress.toString(), function () {
          clearTimeout(reverseTimer);

          if (greetingSent) {
            return;
          }

          greetingSent = true;
          reverseCb.apply(void 0, arguments);
        });
      } catch (E) {
        clearTimeout(reverseTimer);

        if (greetingSent) {
          return;
        }

        greetingSent = true;
        reverseCb(E);
      }
    }
    /**
     * Send data to socket
     *
     * @param {Number} code Response code
     * @param {String|Array} data If data is Array, send a multi-line response
     */

  }, {
    key: "send",
    value: function send(code, data) {
      var payload;

      if (Array.isArray(data)) {
        payload = data.map(function (line, i, arr) {
          return code + (i < arr.length - 1 ? '-' : ' ') + line;
        }).join('\r\n');
      } else {
        payload = [].concat(code || []).concat(data || []).join(' ');
      }

      if (code >= 400) {
        this.session.error = payload;
      }

      if (this._socket && this._socket.writable) {
        this._socket.write(payload + '\r\n');

        this._server.logger.debug({
          tnx: 'send',
          cid: this.id,
          user: this.session.user && this.session.user.username || this.session.user
        }, 'S:', payload);
      }

      if (code === 421) {
        this.close();
      }
    }
    /**
     * Close socket
     */

  }, {
    key: "close",
    value: function close() {
      if (!this._socket.destroyed && this._socket.writable) {
        this._socket.end();
      }

      this._server.connections["delete"](this);

      this._closing = true;
    } // PRIVATE METHODS

    /**
     * Setup socket event handlers
     */

  }, {
    key: "_setListeners",
    value: function _setListeners(callback) {
      var _this5 = this;

      this._socket.on('close', function () {
        return _this5._onClose();
      });

      this._socket.on('error', function (err) {
        return _this5._onError(err);
      });

      this._socket.setTimeout(this._server.options.socketTimeout || SOCKET_TIMEOUT, function () {
        return _this5._onTimeout();
      });

      this._socket.pipe(this._parser);

      if (!this.needsUpgrade) {
        return callback();
      }

      this.upgrade(function () {
        return false;
      }, callback);
    }
    /**
     * Fired when the socket is closed
     * @event
     */

  }, {
    key: "_onClose",
    value: function _onClose()
    /* hadError */
    {
      var _this6 = this;

      if (this._parser) {
        this._parser.closed = true;

        this._socket.unpipe(this._parser);

        this._parser = false;
      }

      if (this._dataStream) {
        this._dataStream.unpipe();

        this._dataStream = null;
      }

      this._server.connections["delete"](this);

      if (this._closed) {
        return;
      }

      this._closed = true;
      this._closing = false;

      this._server.logger.info({
        tnx: 'close',
        cid: this.id,
        host: this.remoteAddress,
        user: this.session.user && this.session.user.username || this.session.user
      }, 'Connection closed to %s', this.clientHostname || this.remoteAddress);

      setImmediate(function () {
        return _this6._server.onClose(_this6.session);
      });
    }
    /**
     * Fired when an error occurs with the socket
     *
     * @event
     * @param {Error} err Error object
     */

  }, {
    key: "_onError",
    value: function _onError(err) {
      if ((err.code === 'ECONNRESET' || err.code === 'EPIPE') && (!this.session.envelope || !this.session.envelope.mailFrom)) {
        // We got a connection error outside transaction. In most cases it means dirty
        // connection ending by the other party, so we can just ignore it
        this.close(); // mark connection as 'closing'

        return;
      }

      err.remote = this.remoteAddress;

      this._server.logger.error({
        err: err,
        tnx: 'error',
        user: this.session.user && this.session.user.username || this.session.user
      }, '%s', err.message);

      this.emit('error', err);
    }
    /**
     * Fired when socket timeouts. Closes connection
     *
     * @event
     */

  }, {
    key: "_onTimeout",
    value: function _onTimeout() {
      this.send(421, 'Timeout - closing connection');
    }
    /**
     * Checks if a selected command is available and ivokes it
     *
     * @param {Buffer} command Single line of data from the client
     * @param {Function} callback Callback to run once the command is processed
     */

  }, {
    key: "_onCommand",
    value: function _onCommand(command, callback) {
      var commandName = (command || '').toString().split(' ').shift().toUpperCase();

      this._server.logger.debug({
        tnx: 'command',
        cid: this.id,
        command: commandName,
        user: this.session.user && this.session.user.username || this.session.user
      }, 'C:', (command || '').toString());

      var handler;

      if (!this._ready) {
        // block spammers that send payloads before server greeting
        return this.send(421, this.name + ' You talk too soon');
      } // block malicious web pages that try to make SMTP calls from an AJAX request


      if (/^(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT) \/.* HTTP\/\d\.\d$/i.test(command)) {
        return this.send(421, 'HTTP requests not allowed');
      }

      callback = callback || function () {
        return false;
      };

      if (this._upgrading) {
        // ignore any commands before TLS upgrade is finished
        return callback();
      }

      if (this._nextHandler) {
        // If we already have a handler method queued up then use this
        handler = this._nextHandler;
        this._nextHandler = undefined;
      } else {
        // detect handler from the command name
        switch (commandName) {
          case 'HELO':
          case 'EHLO':
          case 'LHLO':
            this.openingCommand = commandName;
            break;
        }

        if (this._server.options.lmtp) {
          switch (commandName) {
            case 'HELO':
            case 'EHLO':
              this.send(500, 'Error: ' + commandName + ' not allowed in LMTP server');
              return setImmediate(callback);

            case 'LHLO':
              commandName = 'EHLO';
              break;
          }
        }

        if (this._isSupported(commandName)) {
          handler = this['handler_' + commandName];
        }
      }

      if (!handler) {
        // if the user makes more
        this._unrecognizedCommands++;

        if (this._unrecognizedCommands >= 10) {
          return this.send(421, 'Error: too many unrecognized commands');
        }

        this.send(500, 'Error: command not recognized');
        return setImmediate(callback);
      } // block users that try to fiddle around without logging in


      if (!this.session.user && this._isSupported('AUTH') && commandName !== 'AUTH' && this._maxAllowedUnauthenticatedCommands !== false) {
        this._unauthenticatedCommands++;

        if (this._unauthenticatedCommands >= this._maxAllowedUnauthenticatedCommands) {
          return this.send(421, 'Error: too many unauthenticated commands');
        }
      }

      if (!this.hostNameAppearsAs && commandName && ['MAIL', 'RCPT', 'DATA', 'AUTH'].includes(commandName)) {
        this.send(503, 'Error: send ' + (this._server.options.lmtp ? 'LHLO' : 'HELO/EHLO') + ' first');
        return setImmediate(callback);
      } // Check if authentication is required


      if (!this.session.user && this._isSupported('AUTH') && ['MAIL', 'RCPT', 'DATA'].includes(commandName) && !this._server.options.authOptional) {
        this.send(530, 'Error: authentication Required');
        return setImmediate(callback);
      }

      handler.call(this, command, callback);
    }
    /**
     * Checks that a command is available and is not listed in the disabled commands array
     *
     * @param {String} command Command name
     * @returns {Boolean} Returns true if the command can be used
     */

  }, {
    key: "_isSupported",
    value: function _isSupported(command) {
      command = (command || '').toString().trim().toUpperCase();
      return !this._server.options.disabledCommands.includes(command) && typeof this['handler_' + command] === 'function';
    }
    /**
     * Parses commands like MAIL FROM and RCPT TO. Returns an object with the address and optional arguments.
     *
     * @param {[type]} name Address type, eg 'mail from' or 'rcpt to'
     * @param {[type]} command Data payload to parse
     * @returns {Object|Boolean} Parsed address in the form of {address:, args: {}} or false if parsing failed
     */

  }, {
    key: "_parseAddressCommand",
    value: function _parseAddressCommand(name, command) {
      command = (command || '').toString();
      name = (name || '').toString().trim().toUpperCase();
      var parts = command.split(':');
      command = parts.shift().trim().toUpperCase();
      parts = parts.join(':').trim().split(/\s+/);
      var address = parts.shift();
      var args = false;
      var invalid = false;

      if (name !== command) {
        return false;
      }

      if (!/^<[^<>]*>$/.test(address)) {
        invalid = true;
      } else {
        address = address.substr(1, address.length - 2);
      }

      parts.forEach(function (part) {
        part = part.split('=');
        var key = part.shift().toUpperCase();
        var value = part.join('=') || true;

        if (typeof value === 'string') {
          // decode 'xtext'
          value = value.replace(/\+([0-9A-F]{2})/g, function (match, hex) {
            return unescape('%' + hex);
          });
        }

        if (!args) {
          args = {};
        }

        args[key] = value;
      });

      if (address) {
        // enforce unycode
        address = address.split('@');

        if (address.length !== 2 || !address[0] || !address[1]) {
          // really bad e-mail address validation. was not able to use joi because of the missing unicode support
          invalid = true;
        } else {
          try {
            address = [address[0] || '', '@', _punycode["default"].toUnicode(address[1] || '')].join('');
          } catch (E) {
            this._server.logger.error({
              tnx: 'punycode',
              cid: this.id,
              user: this.session.user && this.session.user.username || this.session.user
            }, 'Failed to process punycode domain "%s". error=%s', address[1], E.message);

            address = [address[0] || '', '@', address[1] || ''].join('');
          }
        }
      }

      return invalid ? false : {
        address: address,
        args: args
      };
    }
    /**
     * Resets or sets up a new session. We reuse existing session object to keep
     * application specific data.
     */

  }, {
    key: "_resetSession",
    value: function _resetSession() {
      var session = this.session; // reset data that might be overwritten

      session.localAddress = this.localAddress;
      session.localPort = this.localPort;
      session.remoteAddress = this.remoteAddress;
      session.remotePort = this.remotePort;
      session.clientHostname = this.clientHostname;
      session.openingCommand = this.openingCommand;
      session.hostNameAppearsAs = this.hostNameAppearsAs;
      session.xClient = this._xClient;
      session.xForward = this._xForward;
      session.transmissionType = this._transmissionType();
      session.tlsOptions = this.tlsOptions; // reset transaction properties

      session.envelope = {
        mailFrom: false,
        rcptTo: []
      };
      session.transaction = this._transactionCounter + 1;
    }
    /**
     * Returns current transmission type
     *
     * @return {String} Transmission type
     */

  }, {
    key: "_transmissionType",
    value: function _transmissionType() {
      var type = this._server.options.lmtp ? 'LMTP' : 'SMTP';

      if (this.openingCommand === 'EHLO') {
        type = 'E' + type;
      }

      if (this.secure) {
        type += 'S';
      }

      if (this.session.user) {
        type += 'A';
      }

      return type;
    }
  }, {
    key: "emitConnection",
    value: function emitConnection() {
      if (!this._canEmitConnection) {
        return;
      }

      this._canEmitConnection = false;
      this.emit('connect', {
        id: this.id,
        localAddress: this.localAddress,
        localPort: this.localPort,
        remoteAddress: this.remoteAddress,
        remotePort: this.remotePort,
        hostNameAppearsAs: this.hostNameAppearsAs,
        clientHostname: this.clientHostname
      });
    } // COMMAND HANDLERS

    /**
     * Processes EHLO. Requires valid hostname as the single argument.
     */

  }, {
    key: "handler_EHLO",
    value: function handler_EHLO(command, callback) {
      var _this7 = this;

      var parts = command.toString().trim().split(/\s+/);
      var hostname = parts[1] || '';

      if (parts.length !== 2) {
        this.send(501, 'Error: syntax: ' + (this._server.options.lmtp ? 'LHLO' : 'EHLO') + ' hostname');
        return callback();
      }

      this.hostNameAppearsAs = hostname.toLowerCase();
      var features = ['PIPELINING', '8BITMIME', 'SMTPUTF8'].filter(function (feature) {
        return !_this7._server.options['hide' + feature];
      });

      if (this._server.options.authMethods.length && this._isSupported('AUTH') && !this.session.user) {
        features.push(['AUTH'].concat(this._server.options.authMethods).join(' '));
      }

      if (!this.secure && this._isSupported('STARTTLS') && !this._server.options.hideSTARTTLS) {
        features.push('STARTTLS');
      }

      if (this._server.options.size) {
        features.push('SIZE' + (this._server.options.hideSize ? '' : ' ' + this._server.options.size));
      } // XCLIENT ADDR removes any special privileges for the client


      if (!this._xClient.has('ADDR') && this._server.options.useXClient && this._isSupported('XCLIENT')) {
        features.push('XCLIENT NAME ADDR PORT PROTO HELO LOGIN');
      } // If client has already issued XCLIENT ADDR then it does not have privileges for XFORWARD anymore


      if (!this._xClient.has('ADDR') && this._server.options.useXForward && this._isSupported('XFORWARD')) {
        features.push('XFORWARD NAME ADDR PORT PROTO HELO IDENT SOURCE');
      }

      this._resetSession(); // EHLO is effectively the same as RSET


      this.send(250, [this.name + ' Nice to meet you, ' + this.clientHostname].concat(features || []));
      callback();
    }
    /**
     * Processes HELO. Requires valid hostname as the single argument.
     */

  }, {
    key: "handler_HELO",
    value: function handler_HELO(command, callback) {
      var parts = command.toString().trim().split(/\s+/);
      var hostname = parts[1] || '';

      if (parts.length !== 2) {
        this.send(501, 'Error: Syntax: HELO hostname');
        return callback();
      }

      this.hostNameAppearsAs = hostname.toLowerCase();

      this._resetSession(); // HELO is effectively the same as RSET


      this.send(250, this.name + ' Nice to meet you, ' + this.clientHostname);
      callback();
    }
    /**
     * Processes QUIT. Closes the connection
     */

  }, {
    key: "handler_QUIT",
    value: function handler_QUIT(command, callback) {
      this.send(221, 'Bye');
      this.close();
      callback();
    }
    /**
     * Processes NOOP. Does nothing but keeps the connection alive
     */

  }, {
    key: "handler_NOOP",
    value: function handler_NOOP(command, callback) {
      this.send(250, 'OK');
      callback();
    }
    /**
     * Processes RSET. Resets user and session info
     */

  }, {
    key: "handler_RSET",
    value: function handler_RSET(command, callback) {
      this._resetSession();

      this.send(250, 'Flushed');
      callback();
    }
    /**
     * Processes HELP. Responds with url to RFC
     */

  }, {
    key: "handler_HELP",
    value: function handler_HELP(command, callback) {
      this.send(214, 'See https://tools.ietf.org/html/rfc5321 for details');
      callback();
    }
    /**
     * Processes VRFY. Does not verify anything
     */

  }, {
    key: "handler_VRFY",
    value: function handler_VRFY(command, callback) {
      this.send(252, 'Try to send something. No promises though');
      callback();
    }
    /**
     * Overrides connection info
     * http://www.postfix.org/XCLIENT_README.html
     *
     * TODO: add unit tests
     */

  }, {
    key: "handler_XCLIENT",
    value: function handler_XCLIENT(command, callback) {
      var _this8 = this;

      // check if user is authorized to perform this command
      if (this._xClient.has('ADDR') || !this._server.options.useXClient) {
        this.send(550, 'Error: Not allowed');
        return callback();
      } // not allowed to change properties if already processing mail


      if (this.session.envelope.mailFrom) {
        this.send(503, 'Error: Mail transaction in progress');
        return callback();
      }

      var allowedKeys = ['NAME', 'ADDR', 'PORT', 'PROTO', 'HELO', 'LOGIN'];
      var parts = command.toString().trim().split(/\s+/);
      var key, value;
      var data = new Map();
      parts.shift(); // remove XCLIENT prefix

      if (!parts.length) {
        this.send(501, 'Error: Bad command parameter syntax');
        return callback();
      }

      var loginValue = false; // parse and validate arguments

      for (var i = 0, len = parts.length; i < len; i++) {
        value = parts[i].split('=');
        key = value.shift();

        if (value.length !== 1 || !allowedKeys.includes(key.toUpperCase())) {
          this.send(501, 'Error: Bad command parameter syntax');
          return callback();
        }

        key = key.toUpperCase(); // value is xtext

        value = (value[0] || '').replace(/\+([0-9A-F]{2})/g, function (match, hex) {
          return unescape('%' + hex);
        });

        if (['[UNAVAILABLE]', '[TEMPUNAVAIL]'].includes(value.toUpperCase())) {
          value = false;
        }

        if (data.has(key)) {
          // ignore duplicate keys
          continue;
        }

        data.set(key, value);

        switch (key) {
          // handled outside the switch
          case 'LOGIN':
            loginValue = value;
            break;

          case 'ADDR':
            if (value) {
              value = value.replace(/^IPV6:/i, ''); // IPv6 addresses are prefixed with "IPv6:"

              if (!_net["default"].isIP(value)) {
                this.send(501, 'Error: Bad command parameter syntax. Invalid address');
                return callback();
              }

              if (_net["default"].isIPv6(value)) {
                value = (0, _ipv6Normalize["default"])(value);
              }

              this._server.logger.info({
                tnx: 'xclient',
                cid: this.id,
                xclientKey: 'ADDR',
                xclient: value,
                user: this.session.user && this.session.user.username || this.session.user
              }, 'XCLIENT from %s through %s', value, this.remoteAddress); // store original value for reference as ADDR:DEFAULT


              if (!this._xClient.has('ADDR:DEFAULT')) {
                this._xClient.set('ADDR:DEFAULT', this.remoteAddress);
              }

              this.remoteAddress = value;
              this.hostNameAppearsAs = false; // reset client provided hostname, require HELO/EHLO
            }

            break;

          case 'NAME':
            value = value || '';

            this._server.logger.info({
              tnx: 'xclient',
              cid: this.id,
              xclientKey: 'NAME',
              xclient: value,
              user: this.session.user && this.session.user.username || this.session.user
            }, 'XCLIENT hostname resolved as "%s"', value); // store original value for reference as NAME:DEFAULT


            if (!this._xClient.has('NAME:DEFAULT')) {
              this._xClient.set('NAME:DEFAULT', this.clientHostname || '');
            }

            this.clientHostname = value.toLowerCase();
            break;

          case 'PORT':
            value = Number(value) || '';

            this._server.logger.info({
              tnx: 'xclient',
              cid: this.id,
              xclientKey: 'PORT',
              xclient: value,
              user: this.session.user && this.session.user.username || this.session.user
            }, 'XCLIENT remote port resolved as "%s"', value); // store original value for reference as NAME:DEFAULT


            if (!this._xClient.has('PORT:DEFAULT')) {
              this._xClient.set('PORT:DEFAULT', this.remotePort || '');
            }

            this.remotePort = value;
            break;

          default: // other values are not relevant

        }

        this._xClient.set(key, value);
      }

      var checkLogin = function checkLogin(done) {
        if (typeof loginValue !== 'string') {
          return done();
        }

        if (!loginValue) {
          // clear authentication session?
          _this8._server.logger.info({
            tnx: 'deauth',
            cid: _this8.id,
            user: _this8.session.user && _this8.session.user.username || _this8.session.user
          }, 'User deauthenticated using %s', 'XCLIENT');

          _this8.session.user = false;
          return done();
        }

        var method = 'SASL_XCLIENT';

        _sasl["default"][method].call(_this8, [loginValue], function (err) {
          if (err) {
            _this8.send(550, err.message);

            _this8.close();

            return;
          }

          done();
        });
      }; // Use [ADDR] if NAME was empty


      if (this.remoteAddress && !this.clientHostname) {
        this.clientHostname = '[' + this.remoteAddress + ']';
      }

      if (data.has('ADDR')) {
        this.emitConnection();
      }

      checkLogin(function () {
        // success
        _this8.send(220, _this8.name + ' ' + (_this8._server.options.lmtp ? 'LMTP' : 'ESMTP') + (_this8._server.options.banner ? ' ' + _this8._server.options.banner : ''));

        callback();
      });
    }
    /**
     * Processes XFORWARD data
     * http://www.postfix.org/XFORWARD_README.html
     *
     * TODO: add unit tests
     */

  }, {
    key: "handler_XFORWARD",
    value: function handler_XFORWARD(command, callback) {
      // check if user is authorized to perform this command
      if (!this._server.options.useXForward) {
        this.send(550, 'Error: Not allowed');
        return callback();
      } // not allowed to change properties if already processing mail


      if (this.session.envelope.mailFrom) {
        this.send(503, 'Error: Mail transaction in progress');
        return callback();
      }

      var allowedKeys = ['NAME', 'ADDR', 'PORT', 'PROTO', 'HELO', 'IDENT', 'SOURCE'];
      var parts = command.toString().trim().split(/\s+/);
      var key, value;
      var data = new Map();
      var hasAddr = false;
      parts.shift(); // remove XFORWARD prefix

      if (!parts.length) {
        this.send(501, 'Error: Bad command parameter syntax');
        return callback();
      } // parse and validate arguments


      for (var i = 0, len = parts.length; i < len; i++) {
        value = parts[i].split('=');
        key = value.shift();

        if (value.length !== 1 || !allowedKeys.includes(key.toUpperCase())) {
          this.send(501, 'Error: Bad command parameter syntax');
          return callback();
        }

        key = key.toUpperCase();

        if (data.has(key)) {
          // ignore duplicate keys
          continue;
        } // value is xtext


        value = (value[0] || '').replace(/\+([0-9A-F]{2})/g, function (match, hex) {
          return unescape('%' + hex);
        });

        if (value.toUpperCase() === '[UNAVAILABLE]') {
          value = false;
        }

        data.set(key, value);

        switch (key) {
          case 'ADDR':
            if (value) {
              value = value.replace(/^IPV6:/i, ''); // IPv6 addresses are prefixed with "IPv6:"

              if (!_net["default"].isIP(value)) {
                this.send(501, 'Error: Bad command parameter syntax. Invalid address');
                return callback();
              }

              if (_net["default"].isIPv6(value)) {
                value = (0, _ipv6Normalize["default"])(value);
              }

              this._server.logger.info({
                tnx: 'xforward',
                cid: this.id,
                xforwardKey: 'ADDR',
                xforward: value,
                user: this.session.user && this.session.user.username || this.session.user
              }, 'XFORWARD from %s through %s', value, this.remoteAddress); // store original value for reference as ADDR:DEFAULT


              if (!this._xClient.has('ADDR:DEFAULT')) {
                this._xClient.set('ADDR:DEFAULT', this.remoteAddress);
              }

              hasAddr = true;
              this.remoteAddress = value;
            }

            break;

          case 'NAME':
            value = value || '';

            this._server.logger.info({
              tnx: 'xforward',
              cid: this.id,
              xforwardKey: 'NAME',
              xforward: value,
              user: this.session.user && this.session.user.username || this.session.user
            }, 'XFORWARD hostname resolved as "%s"', value);

            this.clientHostname = value.toLowerCase();
            break;

          case 'PORT':
            value = Number(value) || 0;

            this._server.logger.info({
              tnx: 'xforward',
              cid: this.id,
              xforwardKey: 'PORT',
              xforward: value,
              user: this.session.user && this.session.user.username || this.session.user
            }, 'XFORWARD port resolved as "%s"', value);

            this.remotePort = value;
            break;

          case 'HELO':
            value = Number(value) || 0;

            this._server.logger.info({
              tnx: 'xforward',
              cid: this.id,
              xforwardKey: 'HELO',
              xforward: value,
              user: this.session.user && this.session.user.username || this.session.user
            }, 'XFORWARD HELO name resolved as "%s"', value);

            this.hostNameAppearsAs = value;
            break;

          default: // other values are not relevant

        }

        this._xForward.set(key, value);
      }

      if (hasAddr) {
        this._canEmitConnection = true;
        this.emitConnection();
      } // success


      this.send(250, 'OK');
      callback();
    }
    /**
     * Upgrades connection to TLS if possible
     */

  }, {
    key: "handler_STARTTLS",
    value: function handler_STARTTLS(command, callback) {
      if (this.secure) {
        this.send(503, 'Error: TLS already active');
        return callback();
      }

      this.send(220, 'Ready to start TLS');
      this.upgrade(callback);
    }
    /**
     * Check if selected authentication is available and delegate auth data to SASL
     */

  }, {
    key: "handler_AUTH",
    value: function handler_AUTH(command, callback) {
      var args = command.toString().trim().split(/\s+/);
      var method;
      var handler;
      args.shift(); // remove AUTH

      method = (args.shift() || '').toString().toUpperCase(); // get METHOD and keep additional arguments in the array

      handler = _sasl["default"]['SASL_' + method];
      handler = handler ? handler.bind(this) : handler;

      if (!this.secure && this._isSupported('STARTTLS') && !this._server.options.hideSTARTTLS && !this._server.options.allowInsecureAuth) {
        this.send(538, 'Error: Must issue a STARTTLS command first');
        return callback();
      }

      if (this.session.user) {
        this.send(503, 'Error: No identity changes permitted');
        return callback();
      }

      if (!this._server.options.authMethods.includes(method) || typeof handler !== 'function') {
        this.send(504, 'Error: Unrecognized authentication type');
        return callback();
      }

      handler(args, callback);
    }
    /**
     * Processes MAIL FROM command, parses address and extra arguments
     */

  }, {
    key: "handler_MAIL",
    value: function handler_MAIL(command, callback) {
      var _this9 = this;

      var parsed = this._parseAddressCommand('mail from', command); // in case we still haven't informed about the new connection emit it


      this.emitConnection(); // sender address can be empty, so we only check if parsing failed or not

      if (!parsed) {
        this.send(501, 'Error: Bad sender address syntax');
        return callback();
      }

      if (this.session.envelope.mailFrom) {
        this.send(503, 'Error: nested MAIL command');
        return callback();
      }

      if (!this._server.options.hideSize && this._server.options.size && parsed.args.SIZE && Number(parsed.args.SIZE) > this._server.options.size) {
        this.send(552, 'Error: message exceeds fixed maximum message size ' + this._server.options.size);
        return callback();
      }

      this._server.onMailFrom(parsed, this.session, function (err) {
        if (err) {
          _this9.send(err.responseCode || 550, err.message);

          return callback();
        }

        _this9.session.envelope.mailFrom = parsed;

        _this9.send(250, 'Accepted');

        callback();
      });
    }
    /**
     * Processes RCPT TO command, parses address and extra arguments
     */

  }, {
    key: "handler_RCPT",
    value: function handler_RCPT(command, callback) {
      var _this10 = this;

      var parsed = this._parseAddressCommand('rcpt to', command); // recipient address can not be empty


      if (!parsed || !parsed.address) {
        this.send(501, 'Error: Bad recipient address syntax');
        return callback();
      }

      if (!this.session.envelope.mailFrom) {
        this.send(503, 'Error: need MAIL command');
        return callback();
      }

      this._server.onRcptTo(parsed, this.session, function (err) {
        if (err) {
          _this10.send(err.responseCode || 550, err.message);

          return callback();
        } // check if the address is already used, if so then overwrite


        for (var i = 0, len = _this10.session.envelope.rcptTo.length; i < len; i++) {
          if (_this10.session.envelope.rcptTo[i].address.toLowerCase() === parsed.address.toLowerCase()) {
            _this10.session.envelope.rcptTo[i] = parsed;
            parsed = false;
            break;
          }
        }

        if (parsed) {
          _this10.session.envelope.rcptTo.push(parsed);
        }

        _this10.send(250, 'Accepted');

        callback();
      });
    }
    /**
     * Processes DATA by forwarding incoming stream to the onData handler
     */

  }, {
    key: "handler_DATA",
    value: function handler_DATA(command, callback) {
      var _this11 = this;

      if (!this.session.envelope.rcptTo.length) {
        this.send(503, 'Error: need RCPT command');
        return callback();
      }

      if (!this._parser) {
        return callback();
      }

      this._dataStream = this._parser.startDataMode(this._server.options.size);

      var close = function close(err, message) {
        var i, len;

        _this11._server.logger.debug({
          tnx: 'data',
          cid: _this11.id,
          bytes: _this11._parser.dataBytes,
          user: _this11.session.user && _this11.session.user.username || _this11.session.user
        }, 'C: <%s bytes of DATA>', _this11._parser.dataBytes);

        if ((0, _typeof2["default"])(_this11._dataStream) === 'object' && _this11._dataStream && _this11._dataStream.readable) {
          _this11._dataStream.removeAllListeners();
        }

        if (err) {
          if (_this11._server.options.lmtp) {
            // separate error response for every recipient when using LMTP
            for (i = 0, len = _this11.session.envelope.rcptTo.length; i < len; i++) {
              _this11.send(err.responseCode || 450, err.message);
            }
          } else {
            // single error response when using SMTP
            _this11.send(err.responseCode || 450, err.message);
          }
        } else if (Array.isArray(message)) {
          // separate responses for every recipient when using LMTP
          message.forEach(function (response) {
            if (/Error\]$/i.test(Object.prototype.toString.call(response))) {
              _this11.send(response.responseCode || 450, response.message);
            } else {
              _this11.send(250, typeof response === 'string' ? response : 'OK: message accepted');
            }
          });
        } else if (_this11._server.options.lmtp) {
          // separate success response for every recipient when using LMTP
          for (i = 0, len = _this11.session.envelope.rcptTo.length; i < len; i++) {
            _this11.send(250, typeof message === 'string' ? message : 'OK: message accepted');
          }
        } else {
          // single success response when using SMTP
          _this11.send(250, typeof message === 'string' ? message : 'OK: message queued');
        }

        _this11._transactionCounter++;
        _this11._unrecognizedCommands = 0; // reset unrecognized commands counter

        _this11._resetSession(); // reset session state


        if ((0, _typeof2["default"])(_this11._parser) === 'object' && _this11._parser) {
          _this11._parser["continue"]();
        }
      };

      this._server.onData(this._dataStream, this.session, function (err, message) {
        // ensure _dataStream is an object and not set to null by premature closing
        // do not continue until the stream has actually ended
        if ((0, _typeof2["default"])(_this11._dataStream) === 'object' && _this11._dataStream && _this11._dataStream.readable) {
          _this11._dataStream.on('end', function () {
            return close(err, message);
          });

          return;
        }

        close(err, message);
      });

      this.send(354, 'End data with <CR><LF>.<CR><LF>');
      callback();
    } // Dummy handlers for some old sendmail specific commands

    /**
     * Processes sendmail WIZ command, upgrades to "wizard mode"
     */

  }, {
    key: "handler_WIZ",
    value: function handler_WIZ(command, callback) {
      var args = command.toString().trim().split(/\s+/);
      var password;
      args.shift(); // remove WIZ

      password = (args.shift() || '').toString(); // require password argument

      if (!password) {
        this.send(500, 'You are no wizard!');
        return callback();
      } // all passwords pass validation, so everyone is a wizard!


      this.session.isWizard = true;
      this.send(200, 'Please pass, oh mighty wizard');
      callback();
    }
    /**
     * Processes sendmail SHELL command, should return interactive shell but this is a dummy function
     * so no actual shell is provided to the client
     */

  }, {
    key: "handler_SHELL",
    value: function handler_SHELL(command, callback) {
      this._server.logger.info({
        tnx: 'shell',
        cid: this.id,
        user: this.session.user && this.session.user.username || this.session.user
      }, 'Client tried to invoke SHELL');

      if (!this.session.isWizard) {
        this.send(500, 'Mere mortals must not mutter that mantra');
        return callback();
      }

      this.send(500, 'Error: Invoking shell is not allowed. This incident will be reported.');
      callback();
    }
    /**
     * Processes sendmail KILL command
     */

  }, {
    key: "handler_KILL",
    value: function handler_KILL(command, callback) {
      this._server.logger.info({
        tnx: 'kill',
        cid: this.id,
        user: this.session.user && this.session.user.username || this.session.user
      }, 'Client tried to invoke KILL');

      this.send(500, 'Can not kill Mom');
      callback();
    }
  }, {
    key: "upgrade",
    value: function upgrade(callback, secureCallback) {
      var _this12 = this;

      this._socket.unpipe(this._parser);

      this._upgrading = true;
      setImmediate(callback); // resume input stream

      var secureContext = this._server.secureContext.get('*');

      var socketOptions = {
        secureContext: secureContext,
        isServer: true,
        server: this._server.server,
        SNICallback: this._server.options.SNICallback
      }; // Apply additional socket options if these are set in the server options

      ['requestCert', 'rejectUnauthorized', 'NPNProtocols', 'SNICallback', 'session', 'requestOCSP'].forEach(function (key) {
        if (key in _this12._server.options) {
          socketOptions[key] = _this12._server.options[key];
        }
      }); // remove all listeners from the original socket besides the error handler

      this._socket.removeAllListeners();

      this._socket.on('error', function (err) {
        return _this12._onError(err);
      }); // upgrade connection


      var secureSocket = new _tls["default"].TLSSocket(this._socket, socketOptions);
      secureSocket.once('close', function () {
        return _this12._onClose();
      });
      secureSocket.once('error', function (err) {
        return _this12._onError(err);
      });
      secureSocket.once('_tlsError', function (err) {
        return _this12._onError(err);
      });
      secureSocket.once('clientError', function (err) {
        return _this12._onError(err);
      });
      secureSocket.setTimeout(this._server.options.socketTimeout || SOCKET_TIMEOUT, function () {
        return _this12._onTimeout();
      });
      secureSocket.on('secure', function () {
        _this12.session.secure = _this12.secure = true;
        _this12._socket = secureSocket;
        _this12._upgrading = false;
        _this12.session.tlsOptions = _this12.tlsOptions = _this12._socket.getCipher();
        var cipher = _this12.session.tlsOptions && _this12.session.tlsOptions.name;

        _this12._server.logger.info({
          tnx: 'starttls',
          cid: _this12.id,
          user: _this12.session.user && _this12.session.user.username || _this12.session.user,
          cipher: cipher
        }, 'Connection upgraded to TLS using ', cipher || 'N/A');

        _this12._socket.pipe(_this12._parser);

        if (typeof secureCallback === 'function') {
          secureCallback();
        }
      });
    }
  }]);
  return SMTPConnection;
}(_events["default"].EventEmitter);

exports.SMTPConnection = SMTPConnection;