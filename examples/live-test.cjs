// Live SMPP server test.
// Credentials are read from environment variables only — never hardcode them.
// Usage:
//   HOST=smsc.example.com PORT=2775 SYSTEM_ID=user PASSWORD=secret \
//     node examples/live-test.cjs                 -> bind + enquire_link + unbind
//   ... DEST=6281234567890 node examples/live-test.cjs  -> also send a submit_sm
const smpp = require('..');

const HOST = process.env.HOST;
const PORT = Number(process.env.PORT || 2775);
const SYSTEM_ID = process.env.SYSTEM_ID;
const PASSWORD = process.env.PASSWORD;
const DEST = process.env.DEST || '';
const MESSAGE = process.env.MESSAGE || 'node-smpp-next live test';

if (!HOST || !SYSTEM_ID || !PASSWORD) {
	console.error('Missing required env vars: HOST, SYSTEM_ID, PASSWORD');
	process.exit(1);
}

function log(...a) {
	console.log(new Date().toISOString(), '-', ...a);
}

function errName(status) {
	for (const k in smpp.errors) if (smpp.errors[k] === status) return k;
	return '0x' + status.toString(16);
}

log(`Connecting to ${HOST}:${PORT} as ${SYSTEM_ID} ...`);

const session = smpp.connect(
	{ host: HOST, port: PORT, connectTimeout: 15000 },
	() => {
		log('TCP connected. Sending bind_transceiver...');
		session.bind_transceiver(
			{ system_id: SYSTEM_ID, password: PASSWORD },
			(pdu) => {
				if (pdu.command_status !== 0) {
					log('BIND FAILED:', errName(pdu.command_status));
					return session.close();
				}
				log('BIND OK. system_id =', pdu.system_id);

				log('Sending enquire_link...');
				session.enquire_link({}, (el) => {
					log('enquire_link_resp status =', errName(el.command_status));

					if (!DEST) {
						log('No DEST set -> skipping submit_sm. Unbinding.');
						return session.unbind(() => session.close());
					}

					log(`Sending submit_sm to ${DEST} ...`);
					session.submit_sm(
						{
							source_addr_ton: smpp.TON.ALPHANUMERIC,
							source_addr: 'SMPPTEST',
							destination_addr: DEST,
							dest_addr_ton: smpp.TON.INTERNATIONAL,
							dest_addr_npi: smpp.NPI.ISDN,
							registered_delivery: 1,
							short_message: MESSAGE,
						},
						(sub) => {
							log(
								'submit_sm_resp status =',
								errName(sub.command_status),
								'| message_id =',
								sub.message_id
							);
							log('Waiting up to 10s for delivery receipt (deliver_sm)...');
							const done = setTimeout(() => {
								log('No DLR within 10s. Unbinding.');
								session.unbind(() => session.close());
							}, 10000);
							session.on('deliver_sm', (dlr) => {
								log('DLR received:', JSON.stringify(dlr.short_message));
								session.send(dlr.response());
								clearTimeout(done);
								session.unbind(() => session.close());
							});
						}
					);
				});
			}
		);
	}
);

session.on('error', (e) => log('SESSION ERROR:', e.message));
session.on('close', () => {
	log('Connection closed.');
	process.exit(0);
});
setTimeout(() => {
	log('Global timeout (30s). Exiting.');
	process.exit(1);
}, 30000);
