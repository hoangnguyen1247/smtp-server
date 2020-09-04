"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports["default"] = void 0;

var _util = _interopRequireDefault(require("util"));

var _crypto = _interopRequireDefault(require("crypto"));

var SASL = {
  SASL_PLAIN: function SASL_PLAIN(args, callback) {
    if (args.length > 1) {
      this.send(501, 'Error: syntax: AUTH PLAIN token');
      return callback();
    }

    if (!args.length) {
      this._nextHandler = SASL.PLAIN_token.bind(this, true);
      this.send(334);
      return callback();
    }

    SASL.PLAIN_token.call(this, false, args[0], callback);
  },
  SASL_LOGIN: function SASL_LOGIN(args, callback) {
    if (args.length > 1) {
      this.send(501, 'Error: syntax: AUTH LOGIN');
      return callback();
    }

    if (!args.length) {
      this._nextHandler = SASL.LOGIN_username.bind(this, true);
      this.send(334, 'VXNlcm5hbWU6');
      return callback();
    }

    SASL.LOGIN_username.call(this, false, args[0], callback);
  },
  SASL_XOAUTH2: function SASL_XOAUTH2(args, callback) {
    if (args.length > 1) {
      this.send(501, 'Error: syntax: AUTH XOAUTH2 token');
      return callback();
    }

    if (!args.length) {
      this._nextHandler = SASL.XOAUTH2_token.bind(this, true);
      this.send(334);
      return callback();
    }

    SASL.XOAUTH2_token.call(this, false, args[0], callback);
  },
  'SASL_CRAM-MD5': function SASL_CRAMMD5(args, callback) {
    if (args.length) {
      this.send(501, 'Error: syntax: AUTH CRAM-MD5');
      return callback();
    }

    var challenge = _util["default"].format('<%s%s@%s>', String(Math.random()).replace(/^[0.]+/, '').substr(0, 8), // random numbers
    Math.floor(Date.now() / 1000), // timestamp
    this.name // hostname
    );

    this._nextHandler = SASL['CRAM-MD5_token'].bind(this, true, challenge);
    this.send(334, Buffer.from(challenge).toString('base64'));
    return callback();
  },
  PLAIN_token: function PLAIN_token(canAbort, token, callback) {
    var _this = this;

    token = (token || '').toString().trim();

    if (canAbort && token === '*') {
      this.send(501, 'Authentication aborted');
      return callback();
    }

    var data = Buffer.from(token, 'base64').toString().split('\x00');

    if (data.length !== 3) {
      this.send(500, 'Error: invalid userdata');
      return callback();
    }

    var username = data[1] || data[0] || '';
    var password = data[2] || '';

    this._server.onAuth({
      method: 'PLAIN',
      username: username,
      password: password
    }, this.session, function (err, response) {
      if (err) {
        _this._server.logger.info({
          err: err,
          tnx: 'autherror',
          cid: _this.id,
          method: 'PLAIN',
          user: username
        }, 'Authentication error for %s using %s. %s', username, 'PLAIN', err.message);

        _this.send(err.responseCode || 535, err.message);

        return callback();
      }

      if (!response.user) {
        _this._server.logger.info({
          tnx: 'authfail',
          cid: _this.id,
          method: 'PLAIN',
          user: username
        }, 'Authentication failed for %s using %s', username, 'PLAIN');

        _this.send(response.responseCode || 535, response.message || 'Error: Authentication credentials invalid');

        return callback();
      }

      _this._server.logger.info({
        tnx: 'auth',
        cid: _this.id,
        method: 'PLAIN',
        user: username
      }, '%s authenticated using %s', username, 'PLAIN');

      _this.session.user = response.user;
      _this.session.transmissionType = _this._transmissionType();

      _this.send(235, 'Authentication successful');

      callback();
    });
  },
  LOGIN_username: function LOGIN_username(canAbort, username, callback) {
    username = (username || '').toString().trim();

    if (canAbort && username === '*') {
      this.send(501, 'Authentication aborted');
      return callback();
    }

    username = Buffer.from(username, 'base64').toString();

    if (!username) {
      this.send(500, 'Error: missing username');
      return callback();
    }

    this._nextHandler = SASL.LOGIN_password.bind(this, username);
    this.send(334, 'UGFzc3dvcmQ6');
    return callback();
  },
  LOGIN_password: function LOGIN_password(username, password, callback) {
    var _this2 = this;

    password = (password || '').toString().trim();

    if (password === '*') {
      this.send(501, 'Authentication aborted');
      return callback();
    }

    password = Buffer.from(password, 'base64').toString();

    this._server.onAuth({
      method: 'LOGIN',
      username: username,
      password: password
    }, this.session, function (err, response) {
      if (err) {
        _this2._server.logger.info({
          err: err,
          tnx: 'autherror',
          cid: _this2.id,
          method: 'LOGIN',
          user: username
        }, 'Authentication error for %s using %s. %s', username, 'LOGIN', err.message);

        _this2.send(err.responseCode || 535, err.message);

        return callback();
      }

      if (!response.user) {
        _this2._server.logger.info({
          tnx: 'authfail',
          cid: _this2.id,
          method: 'LOGIN',
          user: username
        }, 'Authentication failed for %s using %s', username, 'LOGIN');

        _this2.send(response.responseCode || 535, response.message || 'Error: Authentication credentials invalid');

        return callback();
      }

      _this2._server.logger.info({
        tnx: 'auth',
        cid: _this2.id,
        method: 'PLAIN',
        user: username
      }, '%s authenticated using %s', username, 'LOGIN');

      _this2.session.user = response.user;
      _this2.session.transmissionType = _this2._transmissionType();

      _this2.send(235, 'Authentication successful');

      callback();
    });
  },
  XOAUTH2_token: function XOAUTH2_token(canAbort, token, callback) {
    var _this3 = this;

    token = (token || '').toString().trim();

    if (canAbort && token === '*') {
      this.send(501, 'Authentication aborted');
      return callback();
    }

    var username;
    var accessToken; // Find username and access token from the input

    Buffer.from(token, 'base64').toString().split('\x01').forEach(function (part) {
      var part2 = part.split('=');
      var key = part2.shift().toLowerCase();
      var value = part2.join('=').trim();

      if (key === 'user') {
        username = value;
      } else if (key === 'auth') {
        var _value = "";

        var value2 = _value.split(/\s+/);

        if (value2.shift().toLowerCase() === 'bearer') {
          accessToken = value2.join(' ');
        }
      }
    });

    if (!username || !accessToken) {
      this.send(500, 'Error: invalid userdata');
      return callback();
    }

    this._server.onAuth({
      method: 'XOAUTH2',
      username: username,
      accessToken: accessToken
    }, this.session, function (err, response) {
      if (err) {
        _this3._server.logger.info({
          err: err,
          tnx: 'autherror',
          cid: _this3.id,
          method: 'XOAUTH2',
          user: username
        }, 'Authentication error for %s using %s. %s', username, 'XOAUTH2', err.message);

        _this3.send(err.responseCode || 535, err.message);

        return callback();
      }

      if (!response.user) {
        _this3._server.logger.info({
          tnx: 'authfail',
          cid: _this3.id,
          method: 'XOAUTH2',
          user: username
        }, 'Authentication failed for %s using %s', username, 'XOAUTH2');

        _this3._nextHandler = SASL.XOAUTH2_error.bind(_this3);

        _this3.send(response.responseCode || 334, Buffer.from(JSON.stringify(response.data || {})).toString('base64'));

        return callback();
      }

      _this3._server.logger.info({
        tnx: 'auth',
        cid: _this3.id,
        method: 'XOAUTH2',
        user: username
      }, '%s authenticated using %s', username, 'XOAUTH2');

      _this3.session.user = response.user;
      _this3.session.transmissionType = _this3._transmissionType();

      _this3.send(235, 'Authentication successful');

      callback();
    });
  },
  XOAUTH2_error: function XOAUTH2_error(data, callback) {
    this.send(535, 'Error: Username and Password not accepted');
    return callback();
  },
  'CRAM-MD5_token': function CRAMMD5_token(canAbort, challenge, token, callback) {
    var _this4 = this;

    token = (token || '').toString().trim();

    if (canAbort && token === '*') {
      this.send(501, 'Authentication aborted');
      return callback();
    }

    var tokenParts = Buffer.from(token, 'base64').toString().split(' ');
    var username = tokenParts.shift();
    var challengeResponse = (tokenParts.shift() || '').toLowerCase();

    this._server.onAuth({
      method: 'CRAM-MD5',
      username: username,
      validatePassword: function validatePassword(password) {
        var hmac = _crypto["default"].createHmac('md5', password);

        return hmac.update(challenge).digest('hex').toLowerCase() === challengeResponse;
      }
    }, this.session, function (err, response) {
      if (err) {
        _this4._server.logger.info({
          err: err,
          tnx: 'autherror',
          cid: _this4.id,
          method: 'CRAM-MD5',
          user: username
        }, 'Authentication error for %s using %s. %s', username, 'CRAM-MD5', err.message);

        _this4.send(err.responseCode || 535, err.message);

        return callback();
      }

      if (!response.user) {
        _this4._server.logger.info({
          tnx: 'authfail',
          cid: _this4.id,
          method: 'CRAM-MD5',
          user: username
        }, 'Authentication failed for %s using %s', username, 'CRAM-MD5');

        _this4.send(response.responseCode || 535, response.message || 'Error: Authentication credentials invalid');

        return callback();
      }

      _this4._server.logger.info({
        tnx: 'auth',
        cid: _this4.id,
        method: 'CRAM-MD5',
        user: username
      }, '%s authenticated using %s', username, 'CRAM-MD5');

      _this4.session.user = response.user;
      _this4.session.transmissionType = _this4._transmissionType();

      _this4.send(235, 'Authentication successful');

      callback();
    });
  },
  // this is not a real auth but a username validation initiated by SMTP proxy
  SASL_XCLIENT: function SASL_XCLIENT(args, callback) {
    var _this5 = this;

    var username = (args && args[0] || '').toString().trim();

    this._server.onAuth({
      method: 'XCLIENT',
      username: username,
      password: null
    }, this.session, function (err, response) {
      if (err) {
        _this5._server.logger.info({
          err: err,
          tnx: 'autherror',
          cid: _this5.id,
          method: 'XCLIENT',
          user: username
        }, 'Authentication error for %s using %s. %s', username, 'XCLIENT', err.message);

        return callback(err);
      }

      if (!response.user) {
        _this5._server.logger.info({
          tnx: 'authfail',
          cid: _this5.id,
          method: 'XCLIENT',
          user: username
        }, 'Authentication failed for %s using %s', username, 'XCLIENT');

        return callback(new Error('Authentication credentials invalid'));
      }

      _this5._server.logger.info({
        tnx: 'auth',
        cid: _this5.id,
        method: 'XCLIENT',
        user: username
      }, '%s authenticated using %s', username, 'XCLIENT');

      _this5.session.user = response.user;
      _this5.session.transmissionType = _this5._transmissionType();
      callback();
    });
  }
};
var _default = SASL;
exports["default"] = _default;