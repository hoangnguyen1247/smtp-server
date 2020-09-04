"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.SMTPStream = void 0;

var _classCallCheck2 = _interopRequireDefault(require("@babel/runtime/helpers/classCallCheck"));

var _createClass2 = _interopRequireDefault(require("@babel/runtime/helpers/createClass"));

var _assertThisInitialized2 = _interopRequireDefault(require("@babel/runtime/helpers/assertThisInitialized"));

var _inherits2 = _interopRequireDefault(require("@babel/runtime/helpers/inherits"));

var _possibleConstructorReturn2 = _interopRequireDefault(require("@babel/runtime/helpers/possibleConstructorReturn"));

var _getPrototypeOf2 = _interopRequireDefault(require("@babel/runtime/helpers/getPrototypeOf"));

var _defineProperty2 = _interopRequireDefault(require("@babel/runtime/helpers/defineProperty"));

var _stream = _interopRequireDefault(require("stream"));

function _createSuper(Derived) { var hasNativeReflectConstruct = _isNativeReflectConstruct(); return function _createSuperInternal() { var Super = (0, _getPrototypeOf2["default"])(Derived), result; if (hasNativeReflectConstruct) { var NewTarget = (0, _getPrototypeOf2["default"])(this).constructor; result = Reflect.construct(Super, arguments, NewTarget); } else { result = Super.apply(this, arguments); } return (0, _possibleConstructorReturn2["default"])(this, result); }; }

function _isNativeReflectConstruct() { if (typeof Reflect === "undefined" || !Reflect.construct) return false; if (Reflect.construct.sham) return false; if (typeof Proxy === "function") return true; try { Date.prototype.toString.call(Reflect.construct(Date, [], function () {})); return true; } catch (e) { return false; } }

var Writable = _stream["default"].Writable;
var PassThrough = _stream["default"].PassThrough;
/**
 * Incoming SMTP stream parser. Detects and emits commands. If switched to
 * data mode, emits unescaped data events until final .
 *
 * @constructor
 * @param {Object} [options] Optional Stream options object
 */

var SMTPStream = /*#__PURE__*/function (_Writable) {
  (0, _inherits2["default"])(SMTPStream, _Writable);

  var _super = _createSuper(SMTPStream);

  function SMTPStream(options) {
    var _this;

    (0, _classCallCheck2["default"])(this, SMTPStream);
    // init Writable
    _this = _super.call(this, options); // Indicates if the stream is currently in data mode

    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_dataMode", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_dataStream", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_maxBytes", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "dataBytes", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_continueCallback", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_remainder", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "_lastBytes", void 0);
    (0, _defineProperty2["default"])((0, _assertThisInitialized2["default"])(_this), "closed", void 0);
    _this._dataMode = false; // Output stream for the current data mode

    _this._dataStream = null; // How many bytes are allowed for a data stream

    _this._maxBytes = Infinity; // How many bytes have been emitted to data stream

    _this.dataBytes = 0; // Callback to run once data mode is finished

    _this._continueCallback = undefined; // unprocessed chars from the last parsing iteration (used in command mode)

    _this._remainder = ''; // unprocessed bytes from the last parsing iteration (used in data mode)

    _this._lastBytes = undefined;
    _this.closed = false; // once the input stream ends, flush all output without expecting the newline

    _this.on('finish', function () {
      return _this._flushData();
    });

    return _this;
  }
  /**
   * Placeholder command handler. Override this with your own.
   */


  (0, _createClass2["default"])(SMTPStream, [{
    key: "oncommand",
    value: function oncommand(command, callback) {
      throw new Error('Command handler is not set');
    }
    /**
     * Switch to data mode and return output stream. The dots in the stream are unescaped.
     *
     * @returns {Stream} Data stream
     */

  }, {
    key: "startDataMode",
    value: function startDataMode(maxBytes) {
      this._dataMode = true;
      this._maxBytes = maxBytes && Number(maxBytes) || Infinity;
      this.dataBytes = 0;
      this._dataStream = new PassThrough();
      return this._dataStream;
    }
    /**
     * Call this once data mode is over and you have finished processing the data stream
     */

  }, {
    key: "continue",
    value: function _continue() {
      if (typeof this._continueCallback === 'function') {
        this._continueCallback();

        this._continueCallback = undefined;
      } else {
        // indicate that the 'continue' was already called once the stream actually ends
        this._continueCallback = undefined;
      }
    } // PRIVATE METHODS

    /**
     * Writable._write method.
     */

  }, {
    key: "_write",
    value: function _write(chunk, encoding, next) {
      var _this2 = this;

      if (!chunk || !chunk.length) {
        return next();
      }

      var data;
      var pos = 0;
      var newlineRegex;
      var called = false;

      var done = function done() {
        if (called) {
          return;
        }

        called = true;
        next.apply(void 0, arguments);
      };

      if (this.closed) {
        return done();
      }

      if (!this._dataMode) {
        newlineRegex = /\r?\n/g;
        data = this._remainder + chunk.toString('binary');

        var readLine = function readLine() {
          var match;
          var line;
          var buf; // check if the mode is not changed

          if (_this2._dataMode) {
            buf = Buffer.from(data.substr(pos), 'binary');
            _this2._remainder = '';
            return _this2._write(buf, 'buffer', done);
          } // search for the next newline
          // exec keeps count of the last match with lastIndex
          // so it knows from where to start with the next iteration


          if (match = newlineRegex.exec(data)) {
            line = data.substr(pos, match.index - pos);
            pos += line.length + match[0].length;
          } else {
            _this2._remainder = pos < data.length ? data.substr(pos) : '';
            return done();
          }

          _this2.oncommand(Buffer.from(line, 'binary'), readLine);
        }; // start reading lines


        readLine();
      } else {
        this._feedDataStream(chunk, done);
      }
    }
    /**
     * Processes a chunk in data mode. Escape dots are removed and final dot ends the data mode.
     */

  }, {
    key: "_feedDataStream",
    value: function _feedDataStream(chunk, done) {
      var _this3 = this;

      var i;
      var endseq = Buffer.from('\r\n.\r\n');
      var len;
      var handled;
      var buf;

      if (this._lastBytes && this._lastBytes.length) {
        chunk = Buffer.concat([this._lastBytes, chunk], this._lastBytes.length + chunk.length);
        this._lastBytes = undefined;
      }

      len = chunk.length; // check if the data does not start with the end terminator

      if (!this.dataBytes && len >= 3 && Buffer.compare(chunk.slice(0, 3), Buffer.from('.\r\n')) === 0) {
        this._endDataMode(false, chunk.slice(3), done);

        return;
      } // check if the first symbol is a escape dot


      if (!this.dataBytes && len >= 2 && chunk[0] === 0x2e && chunk[1] === 0x2e) {
        chunk = chunk.slice(1);
        len--;
      } // seek for the stream ending


      for (i = 2; i < len - 2; i++) {
        // if the dot is the first char in a line
        if (chunk[i] === 0x2e && chunk[i - 1] === 0x0a) {
          // if the dot matches end terminator
          if (Buffer.compare(chunk.slice(i - 2, i + 3), endseq) === 0) {
            if (i > 2) {
              buf = chunk.slice(0, i);
              this.dataBytes += buf.length;

              this._endDataMode(buf, chunk.slice(i + 3), done);
            } else {
              this._endDataMode(false, chunk.slice(i + 3), done);
            }

            return;
          } // check if the dot is an escape char and remove it


          if (chunk[i + 1] === 0x2e) {
            buf = chunk.slice(0, i);
            this._lastBytes = undefined; // clear remainder bytes

            this.dataBytes += buf.length; // increment byte counter
            // emit what we already have and continue without the dot

            if (this._dataStream.writable) {
              this._dataStream.write(buf);
            }

            return setImmediate(function () {
              return _this3._feedDataStream(chunk.slice(i + 1), done);
            });
          }
        }
      } // keep the last bytes


      if (chunk.length < 4) {
        this._lastBytes = chunk;
      } else {
        this._lastBytes = chunk.slice(chunk.length - 4);
      } // if current chunk is longer than the remainder bytes we keep for later emit the available bytes


      if (this._lastBytes.length < chunk.length) {
        buf = chunk.slice(0, chunk.length - this._lastBytes.length);
        this.dataBytes += buf.length; // write to stream but stop if need to wait for drain

        if (this._dataStream.writable) {
          handled = this._dataStream.write(buf);

          if (!handled) {
            this._dataStream.once('drain', done);
          } else {
            return done();
          }
        } else {
          return done();
        }
      } else {
        // nothing to emit, continue with the input stream
        return done();
      }
    }
    /**
     * Flushes remaining bytes
     */

  }, {
    key: "_flushData",
    value: function _flushData() {
      var line;

      if (this._remainder && !this.closed) {
        line = this._remainder;
        this._remainder = '';
        this.oncommand(Buffer.from(line, 'binary'));
      }
    }
    /**
     * Ends data mode and returns to command mode. Stream is not resumed before #continue is called
     */

  }, {
    key: "_endDataMode",
    value: function _endDataMode(chunk, remainder, callback) {
      var _this4 = this;

      if (this._continueCallback) {
        this._continueCallback = undefined; // wait until the stream is actually over and then continue

        this._dataStream.once('end', callback);
      } else {
        this._continueCallback = function () {
          return _this4._write(remainder, 'buffer', callback);
        };
      }

      this._dataStream.byteLength = this.dataBytes;
      this._dataStream.sizeExceeded = this.dataBytes > this._maxBytes;

      if (chunk && chunk.length && this._dataStream.writable) {
        this._dataStream.end(chunk);
      } else {
        this._dataStream.end();
      }

      this._dataMode = false;
      this._remainder = '';
      this._dataStream = null;
    }
  }]);
  return SMTPStream;
}(Writable);

exports.SMTPStream = SMTPStream;