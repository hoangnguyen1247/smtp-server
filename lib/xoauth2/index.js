"use strict";

var _interopRequireWildcard = require("@babel/runtime/helpers/interopRequireWildcard");

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports["default"] = void 0;

var _typeof2 = _interopRequireDefault(require("@babel/runtime/helpers/typeof"));

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime/helpers/createClass"));

var _assertThisInitialized2 = _interopRequireDefault(require("@babel/runtime/helpers/assertThisInitialized"));

var _inherits2 = _interopRequireDefault(require("@babel/runtime/helpers/inherits"));

var _possibleConstructorReturn2 = _interopRequireDefault(require("@babel/runtime/helpers/possibleConstructorReturn"));

var _getPrototypeOf2 = _interopRequireDefault(require("@babel/runtime/helpers/getPrototypeOf"));

var _defineProperty2 = _interopRequireDefault(require("@babel/runtime/helpers/defineProperty"));

var _stream = require("stream");

var _crypto = _interopRequireDefault(require("crypto"));

var _fetch = _interopRequireDefault(require("../fetch"));

var shared = _interopRequireWildcard(require("../shared"));

function _createSuper(Derived) { var hasNativeReflectConstruct = _isNativeReflectConstruct(); return function _createSuperInternal() { var Super = (0, _getPrototypeOf2["default"])(Derived), result; if (hasNativeReflectConstruct) { var NewTarget = (0, _getPrototypeOf2["default"])(this).constructor; result = Reflect.construct(Super, arguments, NewTarget); } else { result = Super.apply(this, arguments); } return (0, _possibleConstructorReturn2["default"])(this, result); }; }

function _isNativeReflectConstruct() { if (typeof Reflect === "undefined" || !Reflect.construct) return false; if (Reflect.construct.sham) return false; if (typeof Proxy === "function") return true; try { Date.prototype.toString.call(Reflect.construct(Date, [], function () {})); return true; } catch (e) { return false; } }

/**
 * XOAUTH2 access_token generator for Gmail.
 * Create client ID for web applications in Google API console to use it.
 * See Offline Access for receiving the needed refreshToken for an user
 * https://developers.google.com/accounts/docs/OAuth2WebServer#offline
 *
 * Usage for generating access tokens with a custom method using provisionCallback:
 * provisionCallback(user, renew, callback)
 *   * user is the username to get the token for
 *   * renew is a boolean that if true indicates that existing token failed and needs to be renewed
 *   * callback is the callback to run with (error, accessToken [, expires])
 *     * accessToken is a string
 *     * expires is an optional expire time in milliseconds
 * If provisionCallback is used, then Nodemailer does not try to attempt generating the token by itself
 *
 * @constructor
 * @param {Object} options Client information for token generation
 * @param {String} options.user User e-mail address
 * @param {String} options.clientId Client ID value
 * @param {String} options.clientSecret Client secret value
 * @param {String} options.refreshToken Refresh token for an user
 * @param {String} options.accessUrl Endpoint for token generation, defaults to 'https://accounts.google.com/o/oauth2/token'
 * @param {String} options.accessToken An existing valid accessToken
 * @param {String} options.privateKey Private key for JSW
 * @param {Number} options.expires Optional Access Token expire time in ms
 * @param {Number} options.timeout Optional TTL for Access Token in seconds
 * @param {Function} options.provisionCallback Function to run when a new access token is required
 */
var XOAuth2 = /*#__PURE__*/function (_Stream) {
  (0, _inherits2["default"])(XOAuth2, _Stream);

  var _super = _createSuper(XOAuth2);

  function XOAuth2(options, logger) {
    var _this;

    (0, _classCallCheck2["default"])(this, XOAuth2);
    _this = _super.call(this);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "options", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "logger", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "provisionCallback", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "accessToken", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "expires", void 0);
    _this.options = options || {};

    if (options && options.serviceClient) {
      if (!options.privateKey || !options.user) {
        setImmediate(function () {
          return _this.emit('error', new Error('Options "privateKey" and "user" are required for service account!'));
        });
        return (0, _possibleConstructorReturn2["default"])(_this);
      }

      var serviceRequestTimeout = Math.min(Math.max(Number(_this.options.serviceRequestTimeout) || 0, 0), 3600);
      _this.options.serviceRequestTimeout = serviceRequestTimeout || 5 * 60;
    }

    _this.logger = shared.getLogger({
      logger: logger
    }, {
      component: _this.options.component || 'OAuth2'
    });
    _this.provisionCallback = typeof _this.options.provisionCallback === 'function' ? _this.options.provisionCallback : false;
    _this.options.accessUrl = _this.options.accessUrl || 'https://accounts.google.com/o/oauth2/token';
    _this.options.customHeaders = _this.options.customHeaders || {};
    _this.options.customParams = _this.options.customParams || {};
    _this.accessToken = _this.options.accessToken || false;

    if (_this.options.expires && Number(_this.options.expires)) {
      _this.expires = _this.options.expires;
    } else {
      var timeout = Math.max(Number(_this.options.timeout) || 0, 0);
      _this.expires = timeout && Date.now() + timeout * 1000 || 0;
    }

    return _this;
  }
  /**
   * Returns or generates (if previous has expired) a XOAuth2 token
   *
   * @param {Boolean} renew If false then use cached access token (if available)
   * @param {Function} callback Callback function with error object and token string
   */


  (0, _createClass2["default"])(XOAuth2, [{
    key: "getToken",
    value: function getToken(renew, callback) {
      var _this2 = this;

      if (!renew && this.accessToken && (!this.expires || this.expires > Date.now())) {
        return callback(null, this.accessToken);
      }

      var generateCallback = function generateCallback() {
        if (arguments.length <= 0 ? undefined : arguments[0]) {
          _this2.logger.error({
            err: arguments.length <= 0 ? undefined : arguments[0],
            tnx: 'OAUTH2',
            user: _this2.options.user,
            action: 'renew'
          }, 'Failed generating new Access Token for %s', _this2.options.user);
        } else {
          _this2.logger.info({
            tnx: 'OAUTH2',
            user: _this2.options.user,
            action: 'renew'
          }, 'Generated new Access Token for %s', _this2.options.user);
        }

        callback.apply(void 0, arguments);
      };

      if (this.provisionCallback) {
        this.provisionCallback(this.options.user, !!renew, function (err, accessToken, expires) {
          if (!err && accessToken) {
            _this2.accessToken = accessToken;
            _this2.expires = expires || 0;
          }

          generateCallback(err, accessToken);
        });
      } else {
        this.generateToken(generateCallback);
      }
    }
    /**
     * Updates token values
     *
     * @param {String} accessToken New access token
     * @param {Number} timeout Access token lifetime in seconds
     *
     * Emits 'token': { user: User email-address, accessToken: the new accessToken, timeout: TTL in seconds}
     */

  }, {
    key: "updateToken",
    value: function updateToken(accessToken, timeout) {
      this.accessToken = accessToken;
      timeout = Math.max(Number(timeout) || 0, 0);
      this.expires = timeout && Date.now() + timeout * 1000 || 0;
      this.emit('token', {
        user: this.options.user,
        accessToken: accessToken || '',
        expires: this.expires
      });
    }
    /**
     * Generates a new XOAuth2 token with the credentials provided at initialization
     *
     * @param {Function} callback Callback function with error object and token string
     */

  }, {
    key: "generateToken",
    value: function generateToken(callback) {
      var _this3 = this;

      var urlOptions;
      var loggedUrlOptions;

      if (this.options.serviceClient) {
        // service account - https://developers.google.com/identity/protocols/OAuth2ServiceAccount
        var iat = Math.floor(Date.now() / 1000); // unix time

        var tokenData = {
          iss: this.options.serviceClient,
          scope: this.options.scope || 'https://mail.google.com/',
          sub: this.options.user,
          aud: this.options.accessUrl,
          iat: iat,
          exp: iat + this.options.serviceRequestTimeout
        };
        var token;

        try {
          token = this.jwtSignRS256(tokenData);
        } catch (err) {
          return callback(new Error('Can\x27t generate token. Check your auth options'));
        }

        urlOptions = {
          grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          assertion: token
        };
        loggedUrlOptions = {
          grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
          assertion: tokenData
        };
      } else {
        if (!this.options.refreshToken) {
          return callback(new Error('Can\x27t create new access token for user'));
        } // web app - https://developers.google.com/identity/protocols/OAuth2WebServer


        urlOptions = {
          client_id: this.options.clientId || '',
          client_secret: this.options.clientSecret || '',
          refresh_token: this.options.refreshToken,
          grant_type: 'refresh_token'
        };
        loggedUrlOptions = {
          client_id: this.options.clientId || '',
          client_secret: (this.options.clientSecret || '').substr(0, 6) + '...',
          refresh_token: (this.options.refreshToken || '').substr(0, 6) + '...',
          grant_type: 'refresh_token'
        };
      }

      Object.keys(this.options.customParams).forEach(function (key) {
        urlOptions[key] = _this3.options.customParams[key];
        loggedUrlOptions[key] = _this3.options.customParams[key];
      });
      this.logger.debug({
        tnx: 'OAUTH2',
        user: this.options.user,
        action: 'generate'
      }, 'Requesting token using: %s', JSON.stringify(loggedUrlOptions));
      this.postRequest(this.options.accessUrl, urlOptions, this.options, function (error, body) {
        var data;

        if (error) {
          return callback(error);
        }

        try {
          data = JSON.parse(body.toString());
        } catch (E) {
          return callback(E);
        }

        if (!data || (0, _typeof2["default"])(data) !== 'object') {
          _this3.logger.debug({
            tnx: 'OAUTH2',
            user: _this3.options.user,
            action: 'post'
          }, 'Response: %s', (body || '').toString());

          return callback(new Error('Invalid authentication response'));
        }

        var logData = {};
        Object.keys(data).forEach(function (key) {
          if (key !== 'access_token') {
            logData[key] = data[key];
          } else {
            logData[key] = (data[key] || '').toString().substr(0, 6) + '...';
          }
        });

        _this3.logger.debug({
          tnx: 'OAUTH2',
          user: _this3.options.user,
          action: 'post'
        }, 'Response: %s', JSON.stringify(logData));

        if (data.error) {
          return callback(new Error(data.error));
        }

        if (data.access_token) {
          _this3.updateToken(data.access_token, data.expires_in);

          return callback(null, _this3.accessToken);
        }

        return callback(new Error('No access token'));
      });
    }
    /**
     * Converts an access_token and user id into a base64 encoded XOAuth2 token
     *
     * @param {String} [accessToken] Access token string
     * @return {String} Base64 encoded token for IMAP or SMTP login
     */

  }, {
    key: "buildXOAuth2Token",
    value: function buildXOAuth2Token(accessToken) {
      var authData = ['user=' + (this.options.user || ''), 'auth=Bearer ' + (accessToken || this.accessToken), '', ''];
      return Buffer.from(authData.join('\x01'), 'utf-8').toString('base64');
    }
    /**
     * Custom POST request handler.
     * This is only needed to keep paths short in Windows – usually this module
     * is a dependency of a dependency and if it tries to require something
     * like the request module the paths get way too long to handle for Windows.
     * As we do only a simple POST request we do not actually require complicated
     * logic support (no redirects, no nothing) anyway.
     *
     * @param {String} url Url to POST to
     * @param {String|Buffer} payload Payload to POST
     * @param {Function} callback Callback function with (err, buff)
     */

  }, {
    key: "postRequest",
    value: function postRequest(url, payload, params, callback) {
      var returned = false;
      var chunks = [];
      var chunklen = 0;
      var req = (0, _fetch["default"])(url, {
        method: 'post',
        headers: params.customHeaders,
        body: payload,
        allowErrorResponse: true
      });
      req.on('readable', function () {
        var chunk;

        while ((chunk = req.read()) !== null) {
          chunks.push(chunk);
          chunklen += chunk.length;
        }
      });
      req.once('error', function (err) {
        if (returned) {
          return;
        }

        returned = true;
        return callback(err);
      });
      req.once('end', function () {
        if (returned) {
          return;
        }

        returned = true;
        return callback(null, Buffer.concat(chunks, chunklen));
      });
    }
    /**
     * Encodes a buffer or a string into Base64url format
     *
     * @param {Buffer|String} data The data to convert
     * @return {String} The encoded string
     */

  }, {
    key: "toBase64URL",
    value: function toBase64URL(data) {
      if (typeof data === 'string') {
        data = Buffer.from(data);
      }

      return data.toString('base64').replace(/[=]+/g, '') // remove '='s
      .replace(/\+/g, '-') // '+' → '-'
      .replace(/\//g, '_'); // '/' → '_'
    }
    /**
     * Creates a JSON Web Token signed with RS256 (SHA256 + RSA)
     *
     * @param {Object} payload The payload to include in the generated token
     * @return {String} The generated and signed token
     */

  }, {
    key: "jwtSignRS256",
    value: function jwtSignRS256(payload) {
      var _this4 = this;

      payload = ['{"alg":"RS256","typ":"JWT"}', JSON.stringify(payload)].map(function (val) {
        return _this4.toBase64URL(val);
      }).join('.');

      var signature = _crypto["default"].createSign('RSA-SHA256').update(payload).sign(this.options.privateKey);

      return payload + '.' + this.toBase64URL(signature);
    }
  }]);
  return XOAuth2;
}(_stream.Stream);

var _default = XOAuth2;
exports["default"] = _default;