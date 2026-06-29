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

	describe('#231 - user-defined TLVs round-trip by numeric tag', function () {
		it('encodes and decodes a custom TLV addressed by its numeric tag id', function () {
			var tag = 0x3c02; // 15362
			var pdu = new smpp.PDU('submit_sm', {
				destination_addr: '12345',
				short_message: 'x',
			});
			pdu[tag] = Buffer.from('TEST', 'ascii');
			var round = new smpp.PDU(pdu.toBuffer());
			assert.ok(Buffer.isBuffer(round[tag]), 'custom TLV missing on decode');
			assert.equal(round[tag].toString('ascii'), 'TEST');
		});

		it('accepts a custom TLV passed via constructor options', function () {
			var pdu = new smpp.PDU('submit_sm', {
				destination_addr: '12345',
				short_message: 'x',
				15362: Buffer.from('ALEX', 'ascii'),
			});
			var round = new smpp.PDU(pdu.toBuffer());
			assert.equal(round[15362].toString('ascii'), 'ALEX');
		});
	});

	describe('#227 - per-request response timeout', function () {
		var server, port;
		before(function (done) {
			// server that never responds, to trigger the timeout
			server = smpp.createServer(function (session) {
				session.on('bind_transceiver', function () {
					/* intentionally no response */
				});
			});
			server.listen(0, function () {
				port = server.address().port;
				done();
			});
		});
		after(function (done) {
			server.once('close', done);
			server.close();
		});

		it('emits responseTimeout when no _resp arrives in time', function (done) {
			var session = smpp.connect({ host: '127.0.0.1', port: port, responseTimeout: 150 });
			session.on('responseTimeout', function (pdu) {
				assert.equal(pdu.command, 'bind_transceiver');
				session.close();
				done();
			});
			session.on('connect', function () {
				session.bind_transceiver({ system_id: 'a', password: 'b' }, function () {
					done(new Error('should not have received a response'));
				});
			});
		});
	});

	describe('#248 - auto-reconnect on unexpected close', function () {
		it('reconnects and re-binds after the server drops the socket', function (done) {
			var drops = 0;
			var server = smpp.createServer(function (session) {
				session.on('bind_transceiver', function (pdu) {
					session.send(pdu.response());
					if (drops === 0) {
						drops++;
						session.close(); // force an unexpected disconnect once
					} else {
						// second (re)bind: success path
						server.close();
						client.close();
						done();
					}
				});
			});
			var client;
			server.listen(0, function () {
				var port = server.address().port;
				client = smpp.connect({
					host: '127.0.0.1',
					port: port,
					autoReconnect: true,
					reconnectInterval: 100,
				});
				client.on('connect', function () {
					client.bind_transceiver({ system_id: 'a', password: 'b' });
				});
			});
		});
	});

	describe('#249 - session pool', function () {
		it('round-robins submit_sm across bound sessions', function (done) {
			var received = 0;
			var server = smpp.createServer(function (session) {
				session.on('bind_transceiver', function (pdu) {
					session.send(pdu.response());
				});
				session.on('submit_sm', function (pdu) {
					session.send(pdu.response({ message_id: 'ok' }));
				});
			});
			server.listen(0, function () {
				var port = server.address().port;
				var pool = smpp.createPool({
					host: '127.0.0.1',
					port: port,
					size: 2,
					bindOptions: { system_id: 'a', password: 'b' },
				});
				var bound = 0;
				pool.on('bound', function () {
					if (++bound < 2) return;
					var pending = 3;
					for (var i = 0; i < 3; i++) {
						pool.submit_sm({ destination_addr: '1', short_message: 'hi' }, function (pdu) {
							assert.equal(pdu.command_status, 0);
							if (++received === pending) {
								pool.close(function () {
									server.close();
									done();
								});
							}
						});
					}
				});
			});
		});
	});
});
