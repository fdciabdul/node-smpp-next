// src/smpp.ts
import net from "net";
import tls from "tls";
import util from "util";
import { parse } from "url";
import { EventEmitter } from "events";
import { proxy } from "findhit-proxywrap";

// src/defs.ts
import iconv from "iconv-lite";
var types = {
  int8: {
    read: function(buffer, offset) {
      return buffer.readUInt8(offset);
    },
    write: function(value, buffer, offset) {
      value = value || 0;
      buffer.writeUInt8(value, offset);
    },
    size: function() {
      return 1;
    },
    default: 0
  },
  int16: {
    read: function(buffer, offset) {
      return buffer.readUInt16BE(offset);
    },
    write: function(value, buffer, offset) {
      value = value || 0;
      buffer.writeUInt16BE(value, offset);
    },
    size: function() {
      return 2;
    },
    default: 0
  },
  int32: {
    read: function(buffer, offset) {
      return buffer.readUInt32BE(offset);
    },
    write: function(value, buffer, offset) {
      value = value || 0;
      buffer.writeUInt32BE(value, offset);
    },
    size: function() {
      return 4;
    },
    default: 0
  },
  string: {
    read: function(buffer, offset) {
      var length = buffer.readUInt8(offset++);
      return buffer.toString("ascii", offset, offset + length);
    },
    write: function(value, buffer, offset) {
      if (!Buffer.isBuffer(value)) {
        value = Buffer.from(String(value), "ascii");
      }
      buffer.writeUInt8(value.length, offset++);
      value.copy(buffer, offset);
    },
    size: function(value) {
      return (value.length || String(value).length) + 1;
    },
    default: ""
  },
  cstring: {
    read: function(buffer, offset) {
      var length = 0;
      while (buffer[offset + length]) {
        length++;
      }
      return buffer.toString("ascii", offset, offset + length);
    },
    write: function(value, buffer, offset) {
      if (!Buffer.isBuffer(value)) {
        value = Buffer.from(String(value), "ascii");
      }
      value.copy(buffer, offset);
      buffer[offset + value.length] = 0;
    },
    size: function(value) {
      return (value.length || String(value).length) + 1;
    },
    default: ""
  },
  buffer: {
    read: function(buffer, offset) {
      var length = buffer.readUInt8(offset++);
      return buffer.slice(offset, offset + length);
    },
    write: function(value, buffer, offset) {
      buffer.writeUInt8(value.length, offset++);
      if (typeof value == "string") {
        value = Buffer.from(value, "ascii");
      }
      value.copy(buffer, offset);
    },
    size: function(value) {
      return value.length + 1;
    },
    default: Buffer.alloc(0)
  },
  dest_address_array: {
    read: function(buffer, offset) {
      var dest_address, dest_flag, result = [];
      var number_of_dests = buffer.readUInt8(offset++);
      while (number_of_dests-- > 0) {
        dest_flag = buffer.readUInt8(offset++);
        if (dest_flag == 1) {
          dest_address = {
            dest_addr_ton: buffer.readUInt8(offset++),
            dest_addr_npi: buffer.readUInt8(offset++),
            destination_addr: types.cstring.read(buffer, offset)
          };
          offset += types.cstring.size(dest_address.destination_addr);
        } else {
          dest_address = {
            dl_name: types.cstring.read(buffer, offset)
          };
          offset += types.cstring.size(dest_address.dl_name);
        }
        result.push(dest_address);
      }
      return result;
    },
    write: function(value, buffer, offset) {
      buffer.writeUInt8(value.length, offset++);
      value.forEach(function(dest_address) {
        if ("dl_name" in dest_address) {
          buffer.writeUInt8(2, offset++);
          types.cstring.write(dest_address.dl_name, buffer, offset);
          offset += types.cstring.size(dest_address.dl_name);
        } else {
          buffer.writeUInt8(1, offset++);
          buffer.writeUInt8(dest_address.dest_addr_ton || 0, offset++);
          buffer.writeUInt8(dest_address.dest_addr_npi || 0, offset++);
          types.cstring.write(dest_address.destination_addr, buffer, offset);
          offset += types.cstring.size(dest_address.destination_addr);
        }
      });
    },
    size: function(value) {
      var size = 1;
      value.forEach(function(dest_address) {
        if ("dl_name" in dest_address) {
          size += types.cstring.size(dest_address.dl_name) + 1;
        } else {
          size += types.cstring.size(dest_address.destination_addr) + 3;
        }
      });
      return size;
    },
    default: []
  },
  unsuccess_sme_array: {
    read: function(buffer, offset) {
      var unsuccess_sme, result = [];
      var no_unsuccess = buffer.readUInt8(offset++);
      while (no_unsuccess-- > 0) {
        unsuccess_sme = {
          dest_addr_ton: buffer.readUInt8(offset++),
          dest_addr_npi: buffer.readUInt8(offset++),
          destination_addr: types.cstring.read(buffer, offset)
        };
        offset += types.cstring.size(unsuccess_sme.destination_addr);
        unsuccess_sme.error_status_code = buffer.readUInt32BE(offset);
        offset += 4;
        result.push(unsuccess_sme);
      }
      return result;
    },
    write: function(value, buffer, offset) {
      buffer.writeUInt8(value.length, offset++);
      value.forEach(function(unsuccess_sme) {
        buffer.writeUInt8(unsuccess_sme.dest_addr_ton || 0, offset++);
        buffer.writeUInt8(unsuccess_sme.dest_addr_npi || 0, offset++);
        types.cstring.write(unsuccess_sme.destination_addr, buffer, offset);
        offset += types.cstring.size(unsuccess_sme.destination_addr);
        buffer.writeUInt32BE(unsuccess_sme.error_status_code, offset);
        offset += 4;
      });
    },
    size: function(value) {
      var size = 1;
      value.forEach(function(unsuccess_sme) {
        size += types.cstring.size(unsuccess_sme.destination_addr) + 6;
      });
      return size;
    },
    default: []
  }
};
types.tlv = {
  int8: types.int8,
  int16: types.int16,
  int32: types.int32,
  cstring: types.cstring,
  string: {
    read: function(buffer, offset, length) {
      return buffer.toString("ascii", offset, offset + (length || 0));
    },
    write: function(value, buffer, offset) {
      if (typeof value == "string") {
        value = Buffer.from(value, "ascii");
      }
      value.copy(buffer, offset);
    },
    size: function(value) {
      return value.length;
    },
    default: ""
  },
  buffer: {
    read: function(buffer, offset, length) {
      return buffer.slice(offset, offset + (length || 0));
    },
    write: function(value, buffer, offset) {
      if (typeof value == "string") {
        value = Buffer.from(value, "ascii");
      }
      value.copy(buffer, offset);
    },
    size: function(value) {
      return value.length;
    },
    default: null
  }
};
var gsmCoder = {
  // GSM 03.38
  GSM: {
    chars: `@\xA3$\xA5\xE8\xE9\xF9\xEC\xF2\xC7
\xD8\xF8\r\xC5\xE5\u0394_\u03A6\u0393\u039B\u03A9\u03A0\u03A8\u03A3\u0398\u039E\x1B\xC6\xE6\xDF\xC9 !"#\xA4%&'()*+,-./0123456789:;<=>?\xA1ABCDEFGHIJKLMNOPQRSTUVWXYZ\xC4\xD6\xD1\xDC\xA7\xBFabcdefghijklmnopqrstuvwxyz\xE4\xF6\xF1\xFC\xE0`,
    extChars: "\f^{}\\\\[~]|\u20AC",
    escChars: "\n\u039B()\\/<=>\xA1e",
    charRegex: /^[@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1BÆæßÉ !"#¤%&\'()*+,\-./0-9:;<=>?¡A-ZÄÖÑÜ§¿a-zäöñüà\f^{}\\[~\]|€]*$/,
    charListEnc: {},
    extCharListEnc: {},
    charListDec: {},
    extCharListDec: {}
  },
  // GSM 03.38 Turkish Shift Table
  GSM_TR: {
    chars: `@\xA3$\xA5\u20AC\xE9\xF9\u0131\xF2\xC7
\u011E\u011F\r\xC5\xE5\u0394_\u03A6\u0393\u039B\u03A9\u03A0\u03A8\u03A3\u0398\u039E\x1B\u015E\u015F\xDF\xC9 !"#\xA4%&'()*+,-./0123456789:;<=>?\u0130ABCDEFGHIJKLMNOPQRSTUVWXYZ\xC4\xD6\xD1\xDC\xA7\xE7abcdefghijklmnopqrstuvwxyz\xE4\xF6\xF1\xFC\xE0`,
    extCharsEnc: "\f^{}\\\\[~]|",
    escCharsEnc: "\n\u039B()\\/<=>\u0130",
    extCharsDec: "\f^{}\\[~]|\u011E\u0130\u015E\xE7\u20AC\u011F\u0131\u015F",
    escCharsDec: "\n\u039B()/<=>\u0130GIScegis",
    charRegex: /^[@£$¥€éùıòÇ\nĞğ\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1BŞşßÉ !"#¤%&\'()*+,-./0-9:;<=>?İA-ZÄÖÑÜ§ça-zäöñüà\f^{}\\[~\]|ĞİŞç€ğış]*$/,
    charListEnc: {},
    extCharListEnc: {},
    charListDec: {},
    extCharListDec: {}
  },
  // GSM 03.38 Spanish Shift Table
  GSM_ES: {
    chars: `@\xA3$\xA5\xE8\xE9\xF9\xEC\xF2\xC7
\xD8\xF8\r\xC5\xE5\u0394_\u03A6\u0393\u039B\u03A9\u03A0\u03A8\u03A3\u0398\u039E\x1B\xC6\xE6\xDF\xC9 !"#\xA4%&'()*+,-./0123456789:;<=>?\xA1ABCDEFGHIJKLMNOPQRSTUVWXYZ\xC4\xD6\xD1\xDC\xA7\xBFabcdefghijklmnopqrstuvwxyz\xE4\xF6\xF1\xFC\xE0`,
    extChars: "\xE7\f^{}\\\\[~]|\xC1\xCD\xD3\xDA\xE1\u20AC\xED\xF3\xFA",
    escChars: "\xC7\n\u039B()\\/<=>\xA1AIOUaeiou",
    charRegex: /^[@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1BÆæßÉ !"#¤%&\'()*+,-./0-9:;<=>?¡A-ZÄÖÑÜ§¿a-zäöñüàç\f^{}\\[~\]|ÁÍÓÚá€íóú]*$/,
    charListEnc: {},
    extCharListEnc: {},
    charListDec: {},
    extCharListDec: {}
  },
  // GSM 03.38 Portuguese Shift Table
  GSM_PT: {
    chars: "@\xA3$\xA5\xEA\xE9\xFA\xED\xF3\xE7\n\xD4\xF4\r\xC1\xE1\u0394_\xAA\xC7\xC0\u221E^\\\u20AC\xD3|\x1B\xC2\xE2\xCA\xC9 !\"#\xBA%&'()*+,-./0123456789:;<=>?\xCDABCDEFGHIJKLMNOPQRSTUVWXYZ\xC3\xD5\xDA\xDC\xA7~abcdefghijklmnopqrstuvwxyz\xE3\xF5`\xFC\xE0",
    extCharsEnc: "\f\u03A6\u0393^\u03A9\u03A0\u03A8\u03A3\u0398{}\\\\[~]|",
    escCharsEnc: "\n\xAA\xC7\xC0\u221E^\\\u20AC\xD3()\\/<=>\xCD",
    extCharsDec: "\xEA\xE7\f\xD4\xF4\xC1\xE1\u03A6\u0393^\u03A9\u03A0 \u03A8\u03A3\u0398\xCA{}\\[~]|\xC0\xCD\xD3\xDA\xC3\xD5\xC2\u20AC\xED\xF3\xFA\xE3\xF5\xE2",
    escCharsDec: "\xE9\xE7\n\xD4\xF4\xC1\xE1\xAA\xC7\xC0\u221E^\\\\\u20AC\xD3\xC9()/<=>\xCDAIOU\xC3\xD5aeiou\xE3\xF5\xE0",
    charRegex: /^[@£$¥êéúíóç\nÔô\rÁáΔ_ªÇÀ∞^\\€Ó|\x1BÂâÊÉ !"#º%&\'()*+,-./0-9:;<=>?ÍA-ZÃÕÚÜ§~a-zãõ`üàêç\fÔôÁáΦΓ^ΩΠΨΣΘÊ{}\\[~\]|ÀÍÓÚÃÕÂ€íóúãõâ]*$/,
    charListEnc: {},
    extCharListEnc: {},
    charListDec: {},
    extCharListDec: {}
  },
  getCoder: function(encoding) {
    var coder = this.GSM;
    switch (encoding) {
      case 1:
        coder = this.GSM_TR;
        break;
      case 2:
        coder = this.GSM_ES;
        break;
      case 3:
        coder = this.GSM_PT;
        break;
    }
    if (Object.keys(coder.charListEnc).length === 0) {
      for (var i = 0; i < coder.chars.length; i++) {
        coder.charListEnc[coder.chars[i]] = i;
        coder.charListDec[i] = coder.chars[i];
      }
      var extCharsEnc = coder.extCharsEnc || coder.extChars || "";
      var escCharsEnc = coder.escCharsEnc || coder.escChars || "";
      for (var i = 0; i < extCharsEnc.length; i++) {
        coder.extCharListEnc[extCharsEnc[i]] = escCharsEnc[i];
      }
      var extCharsDec = coder.extCharsDec || coder.extChars || "";
      var escCharsDec = coder.escCharsDec || coder.escChars || "";
      for (var i = 0; i < escCharsDec.length; i++) {
        coder.extCharListDec[escCharsDec[i]] = extCharsDec[i];
      }
    }
    return coder;
  },
  encode: function(string, encoding) {
    var coder = this.getCoder(encoding);
    var extCharsEnc = coder.extCharsEnc || coder.extChars || "";
    var extCharRegex = new RegExp("[" + extCharsEnc.replace("]", "\\]") + "]", "g");
    string = string.replace(extCharRegex, function(match) {
      return "\x1B" + coder.extCharListEnc[match];
    });
    var result = [];
    for (var i = 0; i < string.length; i++) {
      result.push(string[i] in coder.charListEnc ? coder.charListEnc[string[i]] : 32);
    }
    return Buffer.from(result);
  },
  decode: function(string, encoding) {
    var coder = this.getCoder(encoding);
    var escCharsDec = coder.escCharsDec || coder.escChars || "";
    var escCharRegex = new RegExp("\x1B([" + escCharsDec + "])", "g");
    var result = "";
    for (var i = 0; i < string.length; i++) {
      result += coder.charListDec[string[i]] || " ";
    }
    return result.replace(escCharRegex, function(match, p1) {
      return coder.extCharListDec[p1];
    });
  },
  detect: function(string) {
    if (gsmCoder.GSM_ES.charRegex.test(string)) {
      return 2;
    }
    if (gsmCoder.GSM_PT.charRegex.test(string)) {
      return 3;
    }
    if (gsmCoder.GSM_TR.charRegex.test(string)) {
      return 1;
    }
    if (gsmCoder.GSM.charRegex.test(string)) {
      return 0;
    }
    return void 0;
  }
};
var encodings = {};
encodings.ASCII = {
  // GSM 03.38
  match: function(value) {
    return gsmCoder.GSM.charRegex.test(value);
  },
  encode: function(value) {
    return gsmCoder.encode(value, 0);
  },
  decode: function(value) {
    return gsmCoder.decode(value, 0);
  }
};
encodings.LATIN1 = {
  match: function(value) {
    return value === iconv.decode(iconv.encode(value, "latin1"), "latin1");
  },
  encode: function(value) {
    return iconv.encode(value, "latin1");
  },
  decode: function(value) {
    return iconv.decode(value, "latin1");
  }
};
encodings.UCS2 = {
  match: function(value) {
    return true;
  },
  encode: function(value) {
    return iconv.encode(value, "utf16-be");
  },
  decode: function(value) {
    return iconv.decode(value, "utf16-be");
  }
};
Object.defineProperty(encodings, "detect", {
  value: function(value) {
    for (var key in encodings) {
      if (encodings[key].match(value)) {
        return key;
      }
    }
    return false;
  }
});
Object.defineProperty(encodings, "default", {
  value: "ASCII",
  writable: true
});
var udhCoder = {
  getUdh: function(buffer) {
    var bufferLength = buffer.length;
    if (bufferLength <= 1) {
      return [];
    }
    var udhList = [];
    var cursor = 1;
    do {
      var udhLength = buffer[cursor + 1] + 2;
      udhList.push(buffer.slice(cursor, cursor + udhLength));
      cursor += udhLength;
    } while (cursor < bufferLength);
    return udhList;
  }
};
var filters = {};
filters.time = {
  encode: function(value) {
    if (!value) {
      return value;
    }
    if (typeof value == "string") {
      if (value.length <= 12) {
        value = ("000000000000" + value).substr(-12) + "000R";
      }
      return value;
    }
    if (value instanceof Date) {
      var result = value.getUTCFullYear().toString().substr(-2);
      result += ("0" + (value.getUTCMonth() + 1)).substr(-2);
      result += ("0" + value.getUTCDate()).substr(-2);
      result += ("0" + value.getUTCHours()).substr(-2);
      result += ("0" + value.getUTCMinutes()).substr(-2);
      result += ("0" + value.getUTCSeconds()).substr(-2);
      result += ("00" + value.getUTCMilliseconds()).substr(-3, 1);
      result += "00+";
      return result;
    }
    return value;
  },
  decode: function(value) {
    if (!value || typeof value != "string") {
      return value;
    }
    if (value.substr(-1) == "R") {
      var result = /* @__PURE__ */ new Date();
      var match = value.match(/^(..)(..)(..)(..)(..)(..).*$/);
      ["FullYear", "Month", "Date", "Hours", "Minutes", "Seconds"].forEach(
        function(method, i) {
          result["set" + method](result["get" + method]() + +match[++i]);
        }
      );
      return result;
    }
    var century = ("000" + (/* @__PURE__ */ new Date()).getUTCFullYear()).substr(-4, 2);
    var result2 = new Date(value.replace(
      /^(..)(..)(..)(..)(..)(..)(.)?.*$/,
      century + "$1-$2-$3 $4:$5:$6:$700 UTC"
    ));
    var match2 = value.match(/(..)([-+])$/);
    if (match2 && match2[1] != "00") {
      var diff = match2[1] * 15;
      if (match2[2] == "+") {
        diff = -diff;
      }
      result2.setMinutes(result2.getMinutes() + diff);
    }
    return result2;
  }
};
filters.message = {
  encode: function(value) {
    if (Buffer.isBuffer(value)) {
      return value;
    }
    var message = typeof value === "string" ? value : value.message;
    if (typeof message === "string" && message) {
      var encoded = false;
      if (value.udh) {
        var udhList = udhCoder.getUdh(value.udh);
        for (var i = 0; i < udhList.length; i++) {
          var udh = udhList[i];
          if (udh[0] === 36 || udh[0] === 37) {
            this.data_coding = consts.ENCODING.ASCII;
            message = gsmCoder.encode(message, udh[2]);
            encoded = true;
            break;
          }
        }
      }
      if (!encoded) {
        var encoding = encodings.default;
        if (this.data_coding === null) {
          encoding = encodings.detect(message);
          this.data_coding = consts.ENCODING[encoding];
        } else if (this.data_coding !== consts.ENCODING.SMSC_DEFAULT) {
          for (var key in consts.ENCODING) {
            if (consts.ENCODING[key] === this.data_coding) {
              encoding = key;
              break;
            }
          }
        }
        message = encodings[encoding].encode(message);
      }
    }
    if (!value.udh || !value.udh.length) {
      return message;
    }
    if ("esm_class" in this) {
      this.esm_class = this.esm_class | consts.ESM_CLASS.UDH_INDICATOR;
    }
    return Buffer.concat([value.udh, message]);
  },
  decode: function(value, skipUdh) {
    if (!Buffer.isBuffer(value) || !("data_coding" in this)) {
      return value;
    }
    var encoding = this.data_coding & 15;
    if (!encoding) {
      encoding = encodings.default;
    } else {
      for (var key in consts.ENCODING) {
        if (consts.ENCODING[key] == encoding) {
          encoding = key;
          break;
        }
      }
    }
    var udhi = this.esm_class & (consts.ESM_CLASS.UDH_INDICATOR || consts.ESM_CLASS.KANNEL_UDH_INDICATOR);
    var result = {};
    if (!skipUdh && value.length && udhi) {
      result.udh = udhCoder.getUdh(value.slice(0, value[0] + 1));
      result.message = value.slice(value[0] + 1);
    } else {
      result.message = value;
    }
    if (result.udh && (encoding === consts.ENCODING.SMSC_DEFAULT || consts.ENCODING.ASCII)) {
      var decoded = false;
      for (var i = 0; i < result.udh.length; i++) {
        var udh = result.udh[i];
        if (udh[0] === 36 || udh[0] === 37) {
          result.message = gsmCoder.decode(result.message, udh[2]);
          decoded = true;
          break;
        }
      }
      if (!decoded && encodings[encoding]) {
        result.message = encodings[encoding].decode(result.message);
      }
    } else if (encodings[encoding]) {
      result.message = encodings[encoding].decode(result.message);
    }
    return result;
  }
};
filters.billing_identification = {
  encode: function(value) {
    if (Buffer.isBuffer(value)) {
      return value;
    }
    var result = Buffer.alloc(value.data.length + 1);
    result.writeUInt8(value.format, 0);
    value.data.copy(result, 1);
    return result;
  },
  decode: function(value) {
    if (!Buffer.isBuffer(value)) {
      return value;
    }
    return {
      format: value.readUInt8(0),
      data: value.slice(1)
    };
  }
};
filters.broadcast_area_identifier = {
  encode: function(value) {
    if (Buffer.isBuffer(value)) {
      return value;
    }
    if (typeof value == "string") {
      value = {
        format: consts.BROADCAST_AREA_FORMAT.NAME,
        data: value
      };
    }
    if (typeof value.data == "string") {
      value.data = Buffer.from(value.data, "ascii");
    }
    var result = Buffer.alloc(value.data.length + 1);
    result.writeUInt8(value.format, 0);
    value.data.copy(result, 1);
    return result;
  },
  decode: function(value) {
    if (!Buffer.isBuffer(value)) {
      return value;
    }
    var result = {
      format: value.readUInt8(0),
      data: value.slice(1)
    };
    if (result.format == consts.BROADCAST_AREA_FORMAT.NAME) {
      result.data = result.data.toString("ascii");
    }
    return result;
  }
};
filters.broadcast_content_type = {
  encode: function(value) {
    if (Buffer.isBuffer(value)) {
      return value;
    }
    var result = Buffer.alloc(3);
    result.writeUInt8(value.network, 0);
    result.writeUInt16BE(value.content_type, 1);
    return result;
  },
  decode: function(value) {
    if (!Buffer.isBuffer(value)) {
      return value;
    }
    return {
      network: value.readUInt8(0),
      content_type: value.readUInt16BE(1)
    };
  }
};
filters.broadcast_frequency_interval = {
  encode: function(value) {
    if (Buffer.isBuffer(value)) {
      return value;
    }
    var result = Buffer.alloc(3);
    result.writeUInt8(value.unit, 0);
    result.writeUInt16BE(value.interval, 1);
    return result;
  },
  decode: function(value) {
    if (!Buffer.isBuffer(value)) {
      return value;
    }
    return {
      unit: value.readUInt8(0),
      interval: value.readUInt16BE(1)
    };
  }
};
filters.callback_num = {
  encode: function(value) {
    if (Buffer.isBuffer(value)) {
      return value;
    }
    var result = Buffer.alloc(value.number.length + 3);
    result.writeUInt8(value.digit_mode || 0, 0);
    result.writeUInt8(value.ton || 0, 1);
    result.writeUInt8(value.npi || 0, 2);
    result.write(value.number, 3, "ascii");
    return result;
  },
  decode: function(value) {
    if (!Buffer.isBuffer(value)) {
      return value;
    }
    return {
      digit_mode: value.readUInt8(0),
      ton: value.readUInt8(1),
      npi: value.readUInt8(2),
      number: value.toString("ascii", 3)
    };
  }
};
filters.callback_num_atag = {
  encode: function(value) {
    if (Buffer.isBuffer(value)) {
      return value;
    }
    var result = Buffer.alloc(value.display.length + 1);
    result.writeUInt8(value.encoding, 0);
    if (typeof value.display == "string") {
      value.display = Buffer.from(value.display, "ascii");
    }
    value.display.copy(result, 1);
    return result;
  },
  decode: function(value) {
    if (!Buffer.isBuffer(value)) {
      return value;
    }
    return {
      encoding: value.readUInt8(0),
      display: value.slice(1)
    };
  }
};
var tlvs = {
  dest_addr_subunit: { id: 5, type: types.tlv.int8 },
  dest_network_type: { id: 6, type: types.tlv.int8 },
  dest_bearer_type: { id: 7, type: types.tlv.int8 },
  dest_telematics_id: { id: 8, type: types.tlv.int16 },
  source_addr_subunit: { id: 13, type: types.tlv.int8 },
  source_network_type: { id: 14, type: types.tlv.int8 },
  source_bearer_type: { id: 15, type: types.tlv.int8 },
  source_telematics_id: { id: 16, type: types.tlv.int16 },
  qos_time_to_live: { id: 23, type: types.tlv.int32 },
  payload_type: { id: 25, type: types.tlv.int8 },
  additional_status_info_text: { id: 29, type: types.tlv.cstring },
  receipted_message_id: { id: 30, type: types.tlv.cstring },
  ms_msg_wait_facilities: { id: 48, type: types.tlv.int8 },
  privacy_indicator: { id: 513, type: types.tlv.int8 },
  source_subaddress: { id: 514, type: types.tlv.buffer },
  dest_subaddress: { id: 515, type: types.tlv.buffer },
  user_message_reference: { id: 516, type: types.tlv.int16 },
  user_response_code: { id: 517, type: types.tlv.int8 },
  source_port: { id: 522, type: types.tlv.int16 },
  dest_port: { id: 523, type: types.tlv.int16 },
  sar_msg_ref_num: { id: 524, type: types.tlv.int16 },
  language_indicator: { id: 525, type: types.tlv.int8 },
  sar_total_segments: { id: 526, type: types.tlv.int8 },
  sar_segment_seqnum: { id: 527, type: types.tlv.int8 },
  sc_interface_version: { id: 528, type: types.tlv.int8 },
  callback_num_pres_ind: { id: 770, type: types.tlv.int8, multiple: true },
  callback_num_atag: { id: 771, type: types.tlv.buffer, filter: filters.callback_num_atag, multiple: true },
  number_of_messages: { id: 772, type: types.tlv.int8 },
  callback_num: { id: 897, type: types.tlv.buffer, filter: filters.callback_num, multiple: true },
  dpf_result: { id: 1056, type: types.tlv.int8 },
  set_dpf: { id: 1057, type: types.tlv.int8 },
  ms_availability_status: { id: 1058, type: types.tlv.int8 },
  network_error_code: { id: 1059, type: types.tlv.buffer },
  message_payload: { id: 1060, type: types.tlv.buffer, filter: filters.message },
  delivery_failure_reason: { id: 1061, type: types.tlv.int8 },
  more_messages_to_send: { id: 1062, type: types.tlv.int8 },
  message_state: { id: 1063, type: types.tlv.int8 },
  congestion_state: { id: 1064, type: types.tlv.int8 },
  ussd_service_op: { id: 1281, type: types.tlv.int8 },
  broadcast_channel_indicator: { id: 1536, type: types.tlv.int8 },
  broadcast_content_type: { id: 1537, type: types.tlv.buffer, filter: filters.broadcast_content_type },
  broadcast_content_type_info: { id: 1538, type: types.tlv.string },
  broadcast_message_class: { id: 1539, type: types.tlv.int8 },
  broadcast_rep_num: { id: 1540, type: types.tlv.int16 },
  broadcast_frequency_interval: { id: 1541, type: types.tlv.buffer, filter: filters.broadcast_frequency_interval },
  broadcast_area_identifier: { id: 1542, type: types.tlv.buffer, filter: filters.broadcast_area_identifier, multiple: true },
  broadcast_error_status: { id: 1543, type: types.tlv.int32, multiple: true },
  broadcast_area_success: { id: 1544, type: types.tlv.int8 },
  broadcast_end_time: { id: 1545, type: types.tlv.string, filter: filters.time },
  broadcast_service_group: { id: 1546, type: types.tlv.string },
  billing_identification: { id: 1547, type: types.tlv.buffer, filter: filters.billing_identification },
  source_network_id: { id: 1549, type: types.tlv.cstring },
  dest_network_id: { id: 1550, type: types.tlv.cstring },
  source_node_id: { id: 1551, type: types.tlv.string },
  dest_node_id: { id: 1552, type: types.tlv.string },
  dest_addr_np_resolution: { id: 1553, type: types.tlv.int8 },
  dest_addr_np_information: { id: 1554, type: types.tlv.string },
  dest_addr_np_country: { id: 1555, type: types.tlv.int32 },
  display_time: { id: 4609, type: types.tlv.int8 },
  sms_signal: { id: 4611, type: types.tlv.int16 },
  ms_validity: { id: 4612, type: types.tlv.buffer },
  alert_on_message_delivery: { id: 4876, type: types.tlv.int8 },
  its_reply_type: { id: 4992, type: types.tlv.int8 },
  its_session_info: { id: 4995, type: types.tlv.buffer }
};
var tlvsById = {};
for (tag in tlvs) {
  tlvsById[tlvs[tag].id] = tlvs[tag];
  tlvs[tag].tag = tag;
}
var tag;
tlvs.alert_on_msg_delivery = tlvs.alert_on_message_delivery;
tlvs.failed_broadcast_area_identifier = tlvs.broadcast_area_identifier;
var commands = {
  alert_notification: {
    id: 258,
    params: {
      source_addr_ton: { type: types.int8 },
      source_addr_npi: { type: types.int8 },
      source_addr: { type: types.cstring },
      esme_addr_ton: { type: types.int8 },
      esme_addr_npi: { type: types.int8 },
      esme_addr: { type: types.cstring }
    }
  },
  bind_receiver: {
    id: 1,
    params: {
      system_id: { type: types.cstring },
      password: { type: types.cstring },
      system_type: { type: types.cstring },
      interface_version: { type: types.int8, default: 80 },
      addr_ton: { type: types.int8 },
      addr_npi: { type: types.int8 },
      address_range: { type: types.cstring }
    }
  },
  bind_receiver_resp: {
    id: 2147483649,
    params: {
      system_id: { type: types.cstring }
    }
  },
  bind_transmitter: {
    id: 2,
    params: {
      system_id: { type: types.cstring },
      password: { type: types.cstring },
      system_type: { type: types.cstring },
      interface_version: { type: types.int8, default: 80 },
      addr_ton: { type: types.int8 },
      addr_npi: { type: types.int8 },
      address_range: { type: types.cstring }
    }
  },
  bind_transmitter_resp: {
    id: 2147483650,
    params: {
      system_id: { type: types.cstring }
    }
  },
  bind_transceiver: {
    id: 9,
    params: {
      system_id: { type: types.cstring },
      password: { type: types.cstring },
      system_type: { type: types.cstring },
      interface_version: { type: types.int8, default: 80 },
      addr_ton: { type: types.int8 },
      addr_npi: { type: types.int8 },
      address_range: { type: types.cstring }
    }
  },
  bind_transceiver_resp: {
    id: 2147483657,
    params: {
      system_id: { type: types.cstring }
    }
  },
  broadcast_sm: {
    id: 273,
    params: {
      service_type: { type: types.cstring },
      source_addr_ton: { type: types.int8 },
      source_addr_npi: { type: types.int8 },
      source_addr: { type: types.cstring },
      message_id: { type: types.cstring },
      priority_flag: { type: types.int8 },
      schedule_delivery_time: { type: types.cstring, filter: filters.time },
      validity_period: { type: types.cstring, filter: filters.time },
      replace_if_present_flag: { type: types.int8 },
      data_coding: { type: types.int8, default: null },
      sm_default_msg_id: { type: types.int8 }
    }
  },
  broadcast_sm_resp: {
    id: 2147483921,
    params: {
      message_id: { type: types.cstring }
    },
    tlvMap: {
      broadcast_area_identifier: "failed_broadcast_area_identifier"
    }
  },
  cancel_broadcast_sm: {
    id: 275,
    params: {
      service_type: { type: types.cstring },
      message_id: { type: types.cstring },
      source_addr_ton: { type: types.int8 },
      source_addr_npi: { type: types.int8 },
      source_addr: { type: types.cstring }
    }
  },
  cancel_broadcast_sm_resp: {
    id: 2147483923
  },
  cancel_sm: {
    id: 8,
    params: {
      service_type: { type: types.cstring },
      message_id: { type: types.cstring },
      source_addr_ton: { type: types.int8 },
      source_addr_npi: { type: types.int8 },
      source_addr: { type: types.cstring },
      dest_addr_ton: { type: types.int8 },
      dest_addr_npi: { type: types.int8 },
      destination_addr: { type: types.cstring }
    }
  },
  cancel_sm_resp: {
    id: 2147483656
  },
  data_sm: {
    id: 259,
    params: {
      service_type: { type: types.cstring },
      source_addr_ton: { type: types.int8 },
      source_addr_npi: { type: types.int8 },
      source_addr: { type: types.cstring },
      dest_addr_ton: { type: types.int8 },
      dest_addr_npi: { type: types.int8 },
      destination_addr: { type: types.cstring },
      esm_class: { type: types.int8 },
      registered_delivery: { type: types.int8 },
      data_coding: { type: types.int8, default: null }
    }
  },
  data_sm_resp: {
    id: 2147483907,
    params: {
      message_id: { type: types.cstring }
    }
  },
  deliver_sm: {
    id: 5,
    params: {
      service_type: { type: types.cstring },
      source_addr_ton: { type: types.int8 },
      source_addr_npi: { type: types.int8 },
      source_addr: { type: types.cstring },
      dest_addr_ton: { type: types.int8 },
      dest_addr_npi: { type: types.int8 },
      destination_addr: { type: types.cstring },
      esm_class: { type: types.int8 },
      protocol_id: { type: types.int8 },
      priority_flag: { type: types.int8 },
      schedule_delivery_time: { type: types.cstring, filter: filters.time },
      validity_period: { type: types.cstring, filter: filters.time },
      registered_delivery: { type: types.int8 },
      replace_if_present_flag: { type: types.int8 },
      data_coding: { type: types.int8, default: null },
      sm_default_msg_id: { type: types.int8 },
      short_message: { type: types.buffer, filter: filters.message }
    }
  },
  deliver_sm_resp: {
    id: 2147483653,
    params: {
      message_id: { type: types.cstring }
    }
  },
  enquire_link: {
    id: 21
  },
  enquire_link_resp: {
    id: 2147483669
  },
  generic_nack: {
    id: 2147483648
  },
  outbind: {
    id: 11,
    params: {
      system_id: { type: types.cstring },
      password: { type: types.cstring }
    }
  },
  query_broadcast_sm: {
    id: 274,
    params: {
      message_id: { type: types.cstring },
      source_addr_ton: { type: types.int8 },
      source_addr_npi: { type: types.int8 },
      source_addr: { type: types.cstring }
    }
  },
  query_broadcast_sm_resp: {
    id: 2147483922,
    params: {
      message_id: { type: types.cstring }
    }
  },
  query_sm: {
    id: 3,
    params: {
      message_id: { type: types.cstring },
      source_addr_ton: { type: types.int8 },
      source_addr_npi: { type: types.int8 },
      source_addr: { type: types.cstring }
    }
  },
  query_sm_resp: {
    id: 2147483651,
    params: {
      message_id: { type: types.cstring },
      final_date: { type: types.cstring, filter: filters.time },
      message_state: { type: types.int8 },
      error_code: { type: types.int8 }
    }
  },
  replace_sm: {
    id: 7,
    params: {
      message_id: { type: types.cstring },
      source_addr_ton: { type: types.int8 },
      source_addr_npi: { type: types.int8 },
      source_addr: { type: types.cstring },
      schedule_delivery_time: { type: types.cstring, filter: filters.time },
      validity_period: { type: types.cstring, filter: filters.time },
      registered_delivery: { type: types.int8 },
      sm_default_msg_id: { type: types.int8 },
      short_message: { type: types.buffer, filter: filters.message }
    }
  },
  replace_sm_resp: {
    id: 2147483655
  },
  submit_multi: {
    id: 33,
    params: {
      service_type: { type: types.cstring },
      source_addr_ton: { type: types.int8 },
      source_addr_npi: { type: types.int8 },
      source_addr: { type: types.cstring },
      dest_address: { type: types.dest_address_array },
      esm_class: { type: types.int8 },
      protocol_id: { type: types.int8 },
      priority_flag: { type: types.int8 },
      schedule_delivery_time: { type: types.cstring, filter: filters.time },
      validity_period: { type: types.cstring, filter: filters.time },
      registered_delivery: { type: types.int8 },
      replace_if_present_flag: { type: types.int8 },
      data_coding: { type: types.int8, default: null },
      sm_default_msg_id: { type: types.int8 },
      short_message: { type: types.buffer, filter: filters.message }
    }
  },
  submit_multi_resp: {
    id: 2147483681,
    params: {
      message_id: { type: types.cstring },
      unsuccess_sme: { type: types.unsuccess_sme_array }
    }
  },
  submit_sm: {
    id: 4,
    params: {
      service_type: { type: types.cstring },
      source_addr_ton: { type: types.int8 },
      source_addr_npi: { type: types.int8 },
      source_addr: { type: types.cstring },
      dest_addr_ton: { type: types.int8 },
      dest_addr_npi: { type: types.int8 },
      destination_addr: { type: types.cstring },
      esm_class: { type: types.int8 },
      protocol_id: { type: types.int8 },
      priority_flag: { type: types.int8 },
      schedule_delivery_time: { type: types.cstring, filter: filters.time },
      validity_period: { type: types.cstring, filter: filters.time },
      registered_delivery: { type: types.int8 },
      replace_if_present_flag: { type: types.int8 },
      data_coding: { type: types.int8, default: null },
      sm_default_msg_id: { type: types.int8 },
      short_message: { type: types.buffer, filter: filters.message }
    }
  },
  submit_sm_resp: {
    id: 2147483652,
    params: {
      message_id: { type: types.cstring }
    }
  },
  unbind: {
    id: 6
  },
  unbind_resp: {
    id: 2147483654
  }
};
var commandsById = {};
for (command in commands) {
  commandsById[commands[command].id] = commands[command];
  commands[command].command = command;
}
var command;
var consts = {
  REGISTERED_DELIVERY: {
    FINAL: 1,
    FAILURE: 2,
    SUCCESS: 3,
    DELIVERY_ACKNOWLEDGEMENT: 4,
    USER_ACKNOWLEDGEMENT: 8,
    INTERMEDIATE: 16
  },
  ESM_CLASS: {
    DATAGRAM: 1,
    FORWARD: 2,
    STORE_FORWARD: 3,
    MC_DELIVERY_RECEIPT: 4,
    DELIVERY_ACKNOWLEDGEMENT: 8,
    USER_ACKNOWLEDGEMENT: 16,
    CONVERSATION_ABORT: 24,
    INTERMEDIATE_DELIVERY: 32,
    UDH_INDICATOR: 64,
    KANNEL_UDH_INDICATOR: 67,
    SET_REPLY_PATH: 128
  },
  MESSAGE_STATE: {
    SCHEDULED: 0,
    ENROUTE: 1,
    DELIVERED: 2,
    EXPIRED: 3,
    DELETED: 4,
    UNDELIVERABLE: 5,
    ACCEPTED: 6,
    UNKNOWN: 7,
    REJECTED: 8,
    SKIPPED: 9
  },
  TON: {
    UNKNOWN: 0,
    INTERNATIONAL: 1,
    NATIONAL: 2,
    NETWORK_SPECIFIC: 3,
    SUBSCRIBER_NUMBER: 4,
    ALPHANUMERIC: 5,
    ABBREVIATED: 6
  },
  NPI: {
    UNKNOWN: 0,
    ISDN: 1,
    DATA: 3,
    TELEX: 4,
    LAND_MOBILE: 6,
    NATIONAL: 8,
    PRIVATE: 9,
    ERMES: 10,
    INTERNET: 14,
    IP: 14,
    WAP: 18
  },
  ENCODING: {
    SMSC_DEFAULT: 0,
    ASCII: 1,
    GSM_TR: 1,
    GSM_ES: 1,
    GSM_PT: 1,
    IA5: 1,
    LATIN1: 3,
    ISO_8859_1: 3,
    BINARY: 4,
    JIS: 5,
    X_0208_1990: 5,
    CYRILLIC: 6,
    ISO_8859_5: 6,
    HEBREW: 7,
    ISO_8859_8: 7,
    UCS2: 8,
    PICTOGRAM: 9,
    ISO_2022_JP: 10,
    EXTENDED_KANJI_JIS: 13,
    X_0212_1990: 13,
    KS_C_5601: 14
  },
  NETWORK: {
    GENERIC: 0,
    GSM: 1,
    TDMA: 2,
    CDMA: 3
  },
  BROADCAST_AREA_FORMAT: {
    NAME: 0,
    ALIAS: 0,
    ELLIPSOID_ARC: 1,
    POLYGON: 2
  },
  BROADCAST_FREQUENCY_INTERVAL: {
    MAX_POSSIBLE: 0,
    SECONDS: 8,
    MINUTES: 9,
    HOURS: 10,
    DAYS: 11,
    WEEKS: 12,
    MONTHS: 13,
    YEARS: 14
  }
};
var errors = {
  ESME_ROK: 0,
  ESME_RINVMSGLEN: 1,
  ESME_RINVCMDLEN: 2,
  ESME_RINVCMDID: 3,
  ESME_RINVBNDSTS: 4,
  ESME_RALYBND: 5,
  ESME_RINVPRTFLG: 6,
  ESME_RINVREGDLVFLG: 7,
  ESME_RSYSERR: 8,
  ESME_RINVSRCADR: 10,
  ESME_RINVDSTADR: 11,
  ESME_RINVMSGID: 12,
  ESME_RBINDFAIL: 13,
  ESME_RINVPASWD: 14,
  ESME_RINVSYSID: 15,
  ESME_RCANCELFAIL: 17,
  ESME_RREPLACEFAIL: 19,
  ESME_RMSGQFUL: 20,
  ESME_RINVSERTYP: 21,
  ESME_RINVNUMDESTS: 51,
  ESME_RINVDLNAME: 52,
  ESME_RINVDESTFLAG: 64,
  ESME_RINVSUBREP: 66,
  ESME_RINVESMCLASS: 67,
  ESME_RCNTSUBDL: 68,
  ESME_RSUBMITFAIL: 69,
  ESME_RINVSRCTON: 72,
  ESME_RINVSRCNPI: 73,
  ESME_RINVDSTTON: 80,
  ESME_RINVDSTNPI: 81,
  ESME_RINVSYSTYP: 83,
  ESME_RINVREPFLAG: 84,
  ESME_RINVNUMMSGS: 85,
  ESME_RTHROTTLED: 88,
  ESME_RINVSCHED: 97,
  ESME_RINVEXPIRY: 98,
  ESME_RINVDFTMSGID: 99,
  ESME_RX_T_APPN: 100,
  ESME_RX_P_APPN: 101,
  ESME_RX_R_APPN: 102,
  ESME_RQUERYFAIL: 103,
  ESME_RINVTLVSTREAM: 192,
  ESME_RTLVNOTALLWD: 193,
  ESME_RINVTLVLEN: 194,
  ESME_RMISSINGTLV: 195,
  ESME_RINVTLVVAL: 196,
  ESME_RDELIVERYFAILURE: 254,
  ESME_RUNKNOWNERR: 255,
  ESME_RSERTYPUNAUTH: 256,
  ESME_RPROHIBITED: 257,
  ESME_RSERTYPUNAVAIL: 258,
  ESME_RSERTYPDENIED: 259,
  ESME_RINVDCS: 260,
  ESME_RINVSRCADDRSUBUNIT: 261,
  ESME_RINVDSTADDRSUBUNIT: 262,
  ESME_RINVBCASTFREQINT: 263,
  ESME_RINVBCASTALIAS_NAME: 264,
  ESME_RINVBCASTAREAFMT: 265,
  ESME_RINVNUMBCAST_AREAS: 266,
  ESME_RINVBCASTCNTTYPE: 267,
  ESME_RINVBCASTMSGCLASS: 268,
  ESME_RBCASTFAIL: 269,
  ESME_RBCASTQUERYFAIL: 270,
  ESME_RBCASTCANCELFAIL: 271,
  ESME_RINVBCAST_REP: 272,
  ESME_RINVBCASTSRVGRP: 273,
  ESME_RINVBCASTCHANIND: 274
};

// src/pdu.ts
var pduHeadParams = [
  "command_length",
  "command_id",
  "command_status",
  "sequence_number"
];
var PDU = class _PDU {
  static {
    this.maxLength = 16384;
  }
  constructor(command, options) {
    if (Buffer.isBuffer(command)) {
      return this.fromBuffer(command);
    }
    options = options || {};
    this.command = command;
    this.command_length = 0;
    this.command_id = commands[command].id;
    this.command_status = options.command_status || 0;
    this.sequence_number = options.sequence_number || 0;
    if (this.command_status) {
      return;
    }
    var params = commands[command].params || {};
    for (var key in params) {
      if (key in options) {
        this[key] = options[key];
      } else if ("default" in params[key]) {
        this[key] = params[key].default;
      } else {
        this[key] = params[key].type.default;
      }
    }
    for (var key in options)
      if (key in tlvs && !(key in params)) {
        this[key] = options[key];
      }
  }
  static commandLength(stream) {
    var buffer = stream.read(4);
    if (!buffer) {
      return false;
    }
    var command_length = buffer.readUInt32BE(0);
    if (command_length > _PDU.maxLength) {
      throw Error(
        "PDU length was too large (" + command_length + ", maximum is " + _PDU.maxLength + ")."
      );
    }
    return command_length;
  }
  static fromStream(stream, command_length) {
    var buffer = stream.read(command_length - 4);
    if (!buffer) {
      return false;
    }
    var commandLengthBuffer = Buffer.alloc(4);
    commandLengthBuffer.writeUInt32BE(command_length, 0);
    var pduBuffer = Buffer.concat([commandLengthBuffer, buffer]);
    return new _PDU(pduBuffer);
  }
  static fromBuffer(buffer) {
    if (buffer.length < 16 || buffer.length < buffer.readUInt32BE(0)) {
      return false;
    }
    return new _PDU(buffer);
  }
  isResponse() {
    return !!(this.command_id & 2147483648);
  }
  response(options) {
    options = options || {};
    options.sequence_number = this.sequence_number;
    if (this.command == "unknown") {
      if (!("command_status" in options)) {
        options.command_status = errors.ESME_RINVCMDID;
      }
      return new _PDU("generic_nack", options);
    }
    return new _PDU(this.command + "_resp", options);
  }
  fromBuffer(buffer) {
    pduHeadParams.forEach(
      function(key2, i) {
        this[key2] = buffer.readUInt32BE(i * 4);
      }.bind(this)
    );
    var params, offset = pduHeadParams.length * 4;
    if (this.command_length > _PDU.maxLength) {
      throw Error(
        "PDU length was too large (" + this.command_length + ", maximum is " + _PDU.maxLength + ")."
      );
    }
    if (commandsById[this.command_id]) {
      this.command = commandsById[this.command_id].command;
      params = commands[this.command].params || {};
    } else {
      this.command = "unknown";
      return this;
    }
    for (var key in params) {
      if (offset >= this.command_length) {
        break;
      }
      this[key] = params[key].type.read(buffer, offset);
      offset += params[key].type.size(this[key]);
    }
    while (offset + 4 <= this.command_length) {
      var tlvId = buffer.readUInt16BE(offset);
      var length = buffer.readUInt16BE(offset + 2);
      offset += 4;
      var tlv = tlvsById[tlvId];
      if (!tlv) {
        this[tlvId] = buffer.slice(offset, offset + length);
        offset += length;
        continue;
      }
      var tag = (commands[this.command].tlvMap || {})[tlv.tag] || tlv.tag;
      if (tlv.multiple) {
        if (!this[tag]) {
          this[tag] = [];
        }
        this[tag].push(tlv.type.read(buffer, offset, length));
      } else {
        this[tag] = tlv.type.read(buffer, offset, length);
      }
      offset += length;
    }
    this._filter("decode");
    return this;
  }
  _filter(func) {
    var self = this;
    var params = commands[this.command].params || {};
    for (var key in self) {
      if (params[key] && params[key].filter) {
        self[key] = params[key].filter[func].call(self, self[key]);
      } else if (tlvs[key] && tlvs[key].filter) {
        if (tlvs[key].multiple) {
          self[key].forEach(function(value, i) {
            self[key][i] = tlvs[key].filter[func].call(self, value, true);
          });
        } else {
          if (key === "message_payload") {
            var skipUdh = self.short_message && self.short_message.message && self.short_message.message.length;
            self[key] = tlvs[key].filter[func].call(self, self[key], skipUdh);
          } else {
            self[key] = tlvs[key].filter[func].call(self, self[key], true);
          }
        }
      }
    }
  }
  _initBuffer() {
    var buffer = Buffer.alloc(this.command_length);
    pduHeadParams.forEach(
      function(key, i) {
        buffer.writeUInt32BE(this[key], i * 4);
      }.bind(this)
    );
    return buffer;
  }
  toBuffer() {
    this.command_length = pduHeadParams.length * 4;
    if (this.command_status) {
      return this._initBuffer();
    }
    this._filter("encode");
    var self = this;
    var params = commands[this.command].params || {};
    for (var key in self) {
      if (params[key]) {
        this.command_length += params[key].type.size(self[key]);
      } else if (tlvs[key]) {
        var values = tlvs[key].multiple ? self[key] : [self[key]];
        values.forEach((value) => {
          this.command_length += tlvs[key].type.size(value) + 4;
        });
      }
    }
    var buffer = this._initBuffer();
    var offset = pduHeadParams.length * 4;
    for (var pkey in params) {
      params[pkey].type.write(self[pkey], buffer, offset);
      offset += params[pkey].type.size(self[pkey]);
    }
    for (var key in self)
      if (tlvs[key] && !(key in params)) {
        var values = tlvs[key].multiple ? self[key] : [self[key]];
        values.forEach(function(value) {
          buffer.writeUInt16BE(tlvs[key].id, offset);
          var length = tlvs[key].type.size(value);
          buffer.writeUInt16BE(length, offset + 2);
          offset += 4;
          tlvs[key].type.write(value, buffer, offset);
          offset += length;
        });
      }
    return buffer;
  }
};

// src/smpp.ts
var proxyTransport = proxy(net, {
  strict: false,
  ignoreStrictExceptions: true
});
var proxyTlsTransport = proxy(tls, {
  strict: false,
  ignoreStrictExceptions: true
});
function Session(options) {
  EventEmitter.call(this);
  this.options = options || {};
  var self = this;
  var clientTransport = net;
  var connectTimeout;
  this._extractPDUs = this._extractPDUs.bind(self);
  this.sequence = 0;
  this.paused = false;
  this.closed = false;
  this.remoteAddress = null;
  this.remotePort = null;
  this.proxyProtocolProxy = null;
  this._busy = false;
  this._callbacks = {};
  this._interval = 0;
  this._command_length = null;
  this._mode = null;
  this._id = Math.floor(Math.random() * (999999 - 1e5)) + 1e5;
  this._prevBytesRead = 0;
  this.rootSocket = function() {
    if (self.socket._parent) return self.socket._parent;
    return self.socket;
  };
  if (options && options.socket) {
    this._mode = "server";
    this.socket = options.socket;
    this.remoteAddress = self.rootSocket().remoteAddress || self.remoteAddress;
    this.remotePort = this.rootSocket().remotePort;
    this.proxyProtocolProxy = this.rootSocket().proxyAddress ? { address: this.rootSocket().proxyAddress, port: this.rootSocket().proxyPort } : false;
  } else {
    this._mode = "client";
    options = options || {};
    if (options.tls) {
      clientTransport = tls;
    }
    if (options.hasOwnProperty("connectTimeout") && options.connectTimeout > 0) {
      connectTimeout = setTimeout(function() {
        if (self.socket) {
          var e = new Error(
            "Timeout of " + options.connectTimeout + "ms while connecting to " + self.options.host + ":" + self.options.port
          );
          e.code = "ETIMEOUT";
          e.timeout = options.connectTimeout;
          self.socket.destroy(e);
        }
      }, options.connectTimeout);
    }
    this.socket = clientTransport.connect(this.options);
    this.socket.on(
      "connect",
      function() {
        clearTimeout(connectTimeout);
        self.remoteAddress = self.rootSocket().remoteAddress || self.remoteAddress;
        self.remotePort = self.rootSocket().remotePort || self.remoteAddress;
        self.debug("server.connected", "connected to server", { secure: options.tls });
        self.emitMetric("server.connected", 1);
        self.emit("connect");
        if (self.options.auto_enquire_link_period) {
          self._interval = setInterval(function() {
            self.enquire_link();
          }, self.options.auto_enquire_link_period);
        }
      }.bind(this)
    );
    this.socket.on(
      "secureConnect",
      function() {
        self.emit("secureConnect");
      }.bind(this)
    );
  }
  this.socket.on("readable", function() {
    var bytesRead = self.socket.bytesRead - self._prevBytesRead;
    if (bytesRead > 0) {
      self.debug("socket.data.in", null, { bytes: bytesRead });
      self.emitMetric("socket.data.in", bytesRead, { bytes: bytesRead });
      self._prevBytesRead = self.socket.bytesRead;
    }
    self._extractPDUs();
  });
  this.socket.on("close", function() {
    self.closed = true;
    clearTimeout(connectTimeout);
    if (self._mode === "server") {
      self.debug("client.disconnected", "client has disconnected");
      self.emitMetric("client.disconnected", 1);
    } else {
      self.debug("server.disconnected", "disconnected from server");
      self.emitMetric("server.disconnected", 1);
    }
    self.emit("close");
    if (self._interval) {
      clearInterval(self._interval);
      self._interval = 0;
    }
  });
  this.socket.on("error", function(e) {
    clearTimeout(connectTimeout);
    if (self._interval) {
      clearInterval(self._interval);
      self._interval = 0;
    }
    self.debug("socket.error", e.message, e);
    self.emitMetric("socket.error", 1, { error: e });
    self.emit("error", e);
  });
}
util.inherits(Session, EventEmitter);
Session.prototype.emitMetric = function(event, value, payload) {
  this.emit("metrics", event || null, value || null, payload || {}, {
    mode: this._mode || null,
    remoteAddress: this.remoteAddress || null,
    remotePort: this.remotePort || null,
    remoteTls: this.options.tls || false,
    sessionId: this._id || null,
    session: this
  });
};
Session.prototype.debug = function(type, msg, payload) {
  if (type === void 0) type = null;
  if (msg === void 0) msg = null;
  if (this.options.debug) {
    var coloredTypes = {
      reset: "\x1B[0m",
      dim: "\x1B[2m",
      "client.connected": "\x1B[1m\x1B[34m",
      "client.disconnected": "\x1B[1m\x1B[31m",
      "server.connected": "\x1B[1m\x1B[34m",
      "server.disconnected": "\x1B[1m\x1B[31m",
      "pdu.command.in": "\x1B[36m",
      "pdu.command.out": "\x1B[32m",
      "pdu.command.error": "\x1B[41m\x1B[30m",
      "socket.error": "\x1B[41m\x1B[30m",
      "socket.data.in": "\x1B[2m",
      "socket.data.out": "\x1B[2m",
      metrics: "\x1B[2m"
    };
    var now = /* @__PURE__ */ new Date();
    var logBuffer = now.toISOString() + " - " + (this._mode === "server" ? "srv" : "cli") + " - " + this._id + " - " + (coloredTypes.hasOwnProperty(type) ? coloredTypes[type] + type + coloredTypes.reset : type) + " - " + (msg !== null ? msg : "") + " - " + coloredTypes.dim + (payload !== void 0 ? JSON.stringify(payload) : "") + coloredTypes.reset;
    if (this.remoteAddress) logBuffer += " - [" + this.remoteAddress + "]";
    console.log(logBuffer);
  }
  if (this.options.debugListener instanceof Function) {
    this.options.debugListener(type, msg, payload);
  }
  this.emit("debug", type, msg, payload);
};
Session.prototype.connect = function() {
  this.sequence = 0;
  this.paused = false;
  this._busy = false;
  this._callbacks = {};
  this.socket.connect(this.options);
};
Session.prototype._extractPDUs = function() {
  if (this._busy) {
    return;
  }
  this._busy = true;
  var pdu;
  while (!this.paused) {
    try {
      if (!this._command_length) {
        this._command_length = PDU.commandLength(this.socket);
        if (!this._command_length) {
          break;
        }
      }
      if (!(pdu = PDU.fromStream(this.socket, this._command_length))) {
        break;
      }
      this.debug("pdu.command.in", pdu.command, pdu);
      this.emitMetric("pdu.command.in", 1, pdu);
    } catch (e) {
      this.debug("pdu.command.error", e.message, e);
      this.emitMetric("pdu.command.error", 1, { error: e });
      this.emit("error", e);
      return;
    }
    this._command_length = null;
    this.emit("pdu", pdu);
    this.emit(pdu.command, pdu);
    if (pdu.isResponse() && this._callbacks[pdu.sequence_number]) {
      this._callbacks[pdu.sequence_number](pdu);
      delete this._callbacks[pdu.sequence_number];
    }
  }
  this._busy = false;
};
Session.prototype.send = function(pdu, responseCallback, sendCallback, failureCallback) {
  if (!this.socket.writable) {
    var errorObject = {
      error: "Socket is not writable",
      errorType: "socket_not_writable"
    };
    this.debug("socket.data.error", null, errorObject);
    this.emitMetric("socket.data.error", 1, errorObject);
    if (failureCallback) {
      pdu.command_status = errors.ESME_RSUBMITFAIL;
      failureCallback(pdu);
    }
    return false;
  }
  if (!pdu.isResponse()) {
    if (!pdu.sequence_number) {
      if (this.sequence == 2147483647) {
        this.sequence = 0;
      }
      pdu.sequence_number = ++this.sequence;
    }
    if (responseCallback) {
      this._callbacks[pdu.sequence_number] = responseCallback;
    }
  } else if (responseCallback && !sendCallback) {
    sendCallback = responseCallback;
  }
  this.debug("pdu.command.out", pdu.command, pdu);
  this.emitMetric("pdu.command.out", 1, pdu);
  var buffer = pdu.toBuffer();
  this.socket.write(
    buffer,
    function(err) {
      if (err) {
        this.debug("socket.data.error", null, {
          error: "Cannot write command " + pdu.command + " to socket",
          errorType: "socket_write_error"
        });
        this.emitMetric("socket.data.error", 1, {
          error: err,
          errorType: "socket_write_error",
          pdu
        });
        if (!pdu.isResponse() && this._callbacks[pdu.sequence_number]) {
          delete this._callbacks[pdu.sequence_number];
        }
        if (failureCallback) {
          pdu.command_status = errors.ESME_RSUBMITFAIL;
          failureCallback(pdu, err);
        }
      } else {
        this.debug("socket.data.out", null, { bytes: buffer.length, error: err });
        this.emitMetric("socket.data.out", buffer.length, { bytes: buffer.length });
        this.emit("send", pdu);
        if (sendCallback) {
          sendCallback(pdu);
        }
      }
    }.bind(this)
  );
  return true;
};
Session.prototype.pause = function() {
  this.paused = true;
};
Session.prototype.resume = function() {
  this.paused = false;
  this._extractPDUs();
};
Session.prototype.close = function(callback) {
  if (callback) {
    if (this.closed) {
      callback();
    } else {
      this.socket.once("close", callback);
    }
  }
  this.socket.end();
};
Session.prototype.destroy = function(callback) {
  if (callback) {
    if (this.closed) {
      callback();
    } else {
      this.socket.once("close", callback);
    }
  }
  this.socket.destroy();
};
var createShortcut = function(command) {
  return function(options, responseCallback, sendCallback, failureCallback) {
    if (typeof options == "function") {
      sendCallback = responseCallback;
      responseCallback = options;
      options = {};
    }
    var pdu = new PDU(command, options);
    return this.send(pdu, responseCallback, sendCallback, failureCallback);
  };
};
for (command in commands) {
  Session.prototype[command] = createShortcut(command);
}
var command;
function Server(options, listener) {
  var self = this, transport;
  this.sessions = [];
  this.isProxiedServer = options && options.isProxiedServer == true;
  if (typeof options == "function") {
    listener = options;
    options = {};
  } else {
    options = options || {};
  }
  if (listener) {
    this.on("session", listener);
  }
  this.tls = options.key && options.cert;
  options.tls = this.tls != null;
  this.options = options;
  self.on("proxiedConnection", function(socket) {
    socket.proxiedConnection = true;
  });
  if (this.isProxiedServer) {
    transport = this.tls ? proxyTlsTransport : proxyTransport;
  } else {
    transport = this.tls ? tls : net;
  }
  transport.Server.call(this, options, function(socket) {
    var session = new Session({
      socket,
      tls: self.options.tls,
      debug: self.options.debug,
      debugListener: self.options.debugListener || null
    });
    session.server = self;
    if (socket.savedEmit) {
      socket.emit = socket.savedEmit;
      socket.savedEmit = null;
    }
    session.debug("client.connected", "client has connected", {
      secure: self.options.tls,
      // Useful information for Proxy protocol debugging & testing
      proxiedServer: self.isProxiedServer,
      proxiedConnection: socket.proxiedConnection || (socket._parent ? socket._parent.proxiedConnection : false) || false,
      remoteAddress: session.remoteAddress,
      remotePort: session.remotePort,
      proxyProtocolProxy: session.proxyProtocolProxy
    });
    self.sessions.push(session);
    socket.on("close", function() {
      self.sessions.splice(self.sessions.indexOf(session), 1);
    });
    self.emit("session", session);
    session.emitMetric("client.connected", 1);
  });
  if (this.isProxiedServer) {
    self.on("connection", function(socket) {
      socket.on("error", function(e) {
        self.emit("error", e);
      });
      if (self.options.autoPrependBuffer) {
        socket.unshift(self.options.autoPrependBuffer);
      }
      socket.savedEmit = socket.emit;
    });
  }
}
function SecureServer(options, listener) {
  Server.call(this, options, listener);
}
function ProxyServer(options, listener) {
  options.isProxiedServer = true;
  Server.call(this, options, listener);
}
function ProxySecureServer(options, listener) {
  options.isProxiedServer = true;
  Server.call(this, options, listener);
}
util.inherits(Server, net.Server);
util.inherits(SecureServer, tls.Server);
util.inherits(ProxyServer, proxyTransport.Server);
util.inherits(ProxySecureServer, proxyTlsTransport.Server);
function createServer(options, listener) {
  if (typeof options == "function") {
    listener = options;
    options = {};
  } else {
    options = options || {};
  }
  if (options.key && options.cert) {
    if (options.enable_proxy_protocol_detection) {
      return new ProxySecureServer(options, listener);
    } else {
      return new SecureServer(options, listener);
    }
  } else {
    if (options.enable_proxy_protocol_detection) {
      return new ProxyServer(options, listener);
    } else {
      return new Server(options, listener);
    }
  }
}
function connect(options, listener) {
  var clientOptions = {};
  if (arguments.length > 1 && typeof listener != "function") {
    clientOptions = {
      host: options,
      port: listener
    };
    listener = arguments[3];
  } else if (typeof options == "string") {
    clientOptions = parse(options);
    clientOptions.host = clientOptions.slashes ? clientOptions.hostname : options;
    clientOptions.tls = clientOptions.protocol === "ssmpp:";
  } else if (typeof options == "function") {
    listener = options;
  } else {
    clientOptions = options || {};
    if (clientOptions.url) {
      options = parse(clientOptions.url);
      clientOptions.host = options.hostname;
      clientOptions.port = options.port;
      clientOptions.tls = options.protocol === "ssmpp:";
    }
  }
  if (clientOptions.tls && !clientOptions.hasOwnProperty("rejectUnauthorized")) {
    clientOptions.rejectUnauthorized = false;
  }
  clientOptions.port = clientOptions.port || (clientOptions.tls ? 3550 : 2775);
  clientOptions.debug = clientOptions.debug || false;
  clientOptions.connectTimeout = clientOptions.connectTimeout || 3e4;
  var session = new Session(clientOptions);
  if (listener) {
    session.on(clientOptions.tls ? "secureConnect" : "connect", function() {
      listener(session);
    });
  }
  return session;
}
var createSession = connect;
function addCommand(command, options) {
  options.command = command;
  commands[command] = options;
  commandsById[options.id] = options;
  Session.prototype[command] = createShortcut(command);
}
function addTLV(tag, options) {
  options.tag = tag;
  tlvs[tag] = options;
  tlvsById[options.id] = options;
}
var {
  REGISTERED_DELIVERY,
  ESM_CLASS,
  MESSAGE_STATE,
  TON,
  NPI,
  ENCODING,
  NETWORK,
  BROADCAST_AREA_FORMAT,
  BROADCAST_FREQUENCY_INTERVAL
} = consts;
var {
  ESME_ROK,
  ESME_RINVMSGLEN,
  ESME_RINVCMDLEN,
  ESME_RINVCMDID,
  ESME_RINVBNDSTS,
  ESME_RALYBND,
  ESME_RINVPRTFLG,
  ESME_RINVREGDLVFLG,
  ESME_RSYSERR,
  ESME_RINVSRCADR,
  ESME_RINVDSTADR,
  ESME_RINVMSGID,
  ESME_RBINDFAIL,
  ESME_RINVPASWD,
  ESME_RINVSYSID,
  ESME_RCANCELFAIL,
  ESME_RREPLACEFAIL,
  ESME_RMSGQFUL,
  ESME_RINVSERTYP,
  ESME_RINVNUMDESTS,
  ESME_RINVDLNAME,
  ESME_RINVDESTFLAG,
  ESME_RINVSUBREP,
  ESME_RINVESMCLASS,
  ESME_RCNTSUBDL,
  ESME_RSUBMITFAIL,
  ESME_RINVSRCTON,
  ESME_RINVSRCNPI,
  ESME_RINVDSTTON,
  ESME_RINVDSTNPI,
  ESME_RINVSYSTYP,
  ESME_RINVREPFLAG,
  ESME_RINVNUMMSGS,
  ESME_RTHROTTLED,
  ESME_RINVSCHED,
  ESME_RINVEXPIRY,
  ESME_RINVDFTMSGID,
  ESME_RX_T_APPN,
  ESME_RX_P_APPN,
  ESME_RX_R_APPN,
  ESME_RQUERYFAIL,
  ESME_RINVTLVSTREAM,
  ESME_RTLVNOTALLWD,
  ESME_RINVTLVLEN,
  ESME_RMISSINGTLV,
  ESME_RINVTLVVAL,
  ESME_RDELIVERYFAILURE,
  ESME_RUNKNOWNERR,
  ESME_RSERTYPUNAUTH,
  ESME_RPROHIBITED,
  ESME_RSERTYPUNAVAIL,
  ESME_RSERTYPDENIED,
  ESME_RINVDCS,
  ESME_RINVSRCADDRSUBUNIT,
  ESME_RINVDSTADDRSUBUNIT,
  ESME_RINVBCASTFREQINT,
  ESME_RINVBCASTALIAS_NAME,
  ESME_RINVBCASTAREAFMT,
  ESME_RINVNUMBCAST_AREAS,
  ESME_RINVBCASTCNTTYPE,
  ESME_RINVBCASTMSGCLASS,
  ESME_RBCASTFAIL,
  ESME_RBCASTQUERYFAIL,
  ESME_RBCASTCANCELFAIL,
  ESME_RINVBCAST_REP,
  ESME_RINVBCASTSRVGRP,
  ESME_RINVBCASTCHANIND
} = errors;
export {
  BROADCAST_AREA_FORMAT,
  BROADCAST_FREQUENCY_INTERVAL,
  ENCODING,
  ESME_RALYBND,
  ESME_RBCASTCANCELFAIL,
  ESME_RBCASTFAIL,
  ESME_RBCASTQUERYFAIL,
  ESME_RBINDFAIL,
  ESME_RCANCELFAIL,
  ESME_RCNTSUBDL,
  ESME_RDELIVERYFAILURE,
  ESME_RINVBCASTALIAS_NAME,
  ESME_RINVBCASTAREAFMT,
  ESME_RINVBCASTCHANIND,
  ESME_RINVBCASTCNTTYPE,
  ESME_RINVBCASTFREQINT,
  ESME_RINVBCASTMSGCLASS,
  ESME_RINVBCASTSRVGRP,
  ESME_RINVBCAST_REP,
  ESME_RINVBNDSTS,
  ESME_RINVCMDID,
  ESME_RINVCMDLEN,
  ESME_RINVDCS,
  ESME_RINVDESTFLAG,
  ESME_RINVDFTMSGID,
  ESME_RINVDLNAME,
  ESME_RINVDSTADDRSUBUNIT,
  ESME_RINVDSTADR,
  ESME_RINVDSTNPI,
  ESME_RINVDSTTON,
  ESME_RINVESMCLASS,
  ESME_RINVEXPIRY,
  ESME_RINVMSGID,
  ESME_RINVMSGLEN,
  ESME_RINVNUMBCAST_AREAS,
  ESME_RINVNUMDESTS,
  ESME_RINVNUMMSGS,
  ESME_RINVPASWD,
  ESME_RINVPRTFLG,
  ESME_RINVREGDLVFLG,
  ESME_RINVREPFLAG,
  ESME_RINVSCHED,
  ESME_RINVSERTYP,
  ESME_RINVSRCADDRSUBUNIT,
  ESME_RINVSRCADR,
  ESME_RINVSRCNPI,
  ESME_RINVSRCTON,
  ESME_RINVSUBREP,
  ESME_RINVSYSID,
  ESME_RINVSYSTYP,
  ESME_RINVTLVLEN,
  ESME_RINVTLVSTREAM,
  ESME_RINVTLVVAL,
  ESME_RMISSINGTLV,
  ESME_RMSGQFUL,
  ESME_ROK,
  ESME_RPROHIBITED,
  ESME_RQUERYFAIL,
  ESME_RREPLACEFAIL,
  ESME_RSERTYPDENIED,
  ESME_RSERTYPUNAUTH,
  ESME_RSERTYPUNAVAIL,
  ESME_RSUBMITFAIL,
  ESME_RSYSERR,
  ESME_RTHROTTLED,
  ESME_RTLVNOTALLWD,
  ESME_RUNKNOWNERR,
  ESME_RX_P_APPN,
  ESME_RX_R_APPN,
  ESME_RX_T_APPN,
  ESM_CLASS,
  MESSAGE_STATE,
  NETWORK,
  NPI,
  PDU,
  REGISTERED_DELIVERY,
  SecureServer,
  Server,
  Session,
  TON,
  addCommand,
  addTLV,
  commands,
  commandsById,
  connect,
  consts,
  createServer,
  createSession,
  encodings,
  errors,
  filters,
  gsmCoder,
  tlvs,
  tlvsById,
  types
};
//# sourceMappingURL=smpp.mjs.map