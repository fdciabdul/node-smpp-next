var assert = require('assert'),
	smpp = require('..'),
	Buffer = require('buffer').Buffer;

// Regression tests for issues ported from upstream farhadi/node-smpp.
describe('upstream issue fixes', function () {

	describe('#229 / #256 - tolerant short_message encoding', function () {
		it('should not crash when short_message is a number', function () {
			var pdu = new smpp.PDU('submit_sm', {
				destination_addr: '12345',
				short_message: 123,
			});
			var buf;
			assert.doesNotThrow(function () {
				buf = pdu.toBuffer();
			});
			var round = new smpp.PDU(buf);
			assert.equal(round.short_message.message, '123');
		});

		it('should not crash when short_message is undefined', function () {
			var pdu = new smpp.PDU('submit_sm', { destination_addr: '12345' });
			pdu.short_message = undefined;
			assert.doesNotThrow(function () {
				pdu.toBuffer();
			});
		});

		it('should not crash when short_message is null', function () {
			var pdu = new smpp.PDU('submit_sm', {
				destination_addr: '12345',
				short_message: null,
			});
			assert.doesNotThrow(function () {
				pdu.toBuffer();
			});
		});
	});

	describe('#66 / #252 - DCS-aware encoding detection on decode', function () {
		function decodeWith(data_coding, buffer) {
			var ctx = { data_coding: data_coding, esm_class: 0 };
			return smpp.filters.message.decode.call(ctx, buffer, false);
		}

		it('decodes UCS2 (data_coding 0x08)', function () {
			var buf = smpp.encodings.UCS2.encode('héllo');
			assert.equal(decodeWith(0x08, buf).message, 'héllo');
		});

		it('treats DCS 0xF8 as default alphabet, not UCS2 (low-nibble trap)', function () {
			// 0xF8: data-coding/message-class group, bit2 = 0 => default (GSM/ASCII).
			// Old code used (0xF8 & 0x0F) = 8 => UCS2, mangling the text.
			var buf = smpp.encodings.ASCII.encode('test');
			assert.equal(decodeWith(0xf8, buf).message, 'test');
		});

		it('treats DCS 0xF4 as binary (returns raw buffer)', function () {
			var buf = Buffer.from([0x01, 0x02, 0x03]);
			var out = decodeWith(0xf4, buf).message;
			assert.ok(Buffer.isBuffer(out));
			assert.deepEqual([].slice.call(out), [1, 2, 3]);
		});

		it('keeps low data_coding values working (0x00 => default ASCII)', function () {
			var buf = smpp.encodings.ASCII.encode('hi');
			assert.equal(decodeWith(0x00, buf).message, 'hi');
		});
	});

	describe('#214 - proxy support without GPLv3 dependency by default', function () {
		it('creates a plain server without requiring findhit-proxywrap', function () {
			var server = smpp.createServer();
			assert.ok(server);
			server.close && server.close();
		});
	});
});
