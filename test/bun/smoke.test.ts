// Bun-native smoke test. Run with: bun test test/bun
// Exercises a real local client <-> server bind + submit_sm roundtrip.
import { test, expect } from 'bun:test';
// Import the built CJS bundle (works under Bun's CJS interop).
const smpp = require('../../dist/smpp.js');

test('PDU encodes/decodes submit_sm', () => {
	const pdu = new smpp.PDU('submit_sm', {
		destination_addr: '12345',
		short_message: 'hello',
	});
	const buf = pdu.toBuffer();
	expect(buf.length).toBeGreaterThan(16);
	const round = new smpp.PDU(buf);
	expect(round.command).toBe('submit_sm');
	expect(round.destination_addr).toBe('12345');
});

test('local server bind_transceiver + submit_sm roundtrip', async () => {
	const server = smpp.createServer({}, (session: any) => {
		session.on('bind_transceiver', (pdu: any) => {
			session.send(pdu.response());
		});
		session.on('submit_sm', (pdu: any) => {
			session.send(pdu.response({ message_id: 'abc123' }));
		});
	});

	await new Promise<void>((resolve) => server.listen(0, resolve));
	const port = server.address().port;

	const result = await new Promise<any>((resolve, reject) => {
		const session = smpp.connect({ host: '127.0.0.1', port }, () => {
			session.bind_transceiver(
				{ system_id: 'u', password: 'p' },
				(bindResp: any) => {
					expect(bindResp.command_status).toBe(0);
					session.submit_sm(
						{ destination_addr: '12345', short_message: 'hi' },
						(submitResp: any) => {
							session.close();
							resolve(submitResp);
						}
					);
				}
			);
		});
		session.on('error', reject);
	});

	expect(result.command_status).toBe(0);
	expect(result.message_id).toBe('abc123');
	await new Promise<void>((resolve) => server.close(resolve));
});
