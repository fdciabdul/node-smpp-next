import net from 'net';
import tls from 'tls';
import util from 'util';
import { parse } from 'url';
import { EventEmitter } from 'events';
import * as defs from './defs';
import { PDU } from './pdu';

// `findhit-proxywrap` pulls in a GPLv3 transitive dependency (findhit-util).
// To keep the core package free of that license obligation (issue #214) it is
// declared as an optional dependency and loaded lazily — only when the proxy
// protocol feature is actually used. Core client/server usage never touches it.
let _proxyTransport: any = null;
let _proxyTlsTransport: any = null;

function loadProxy(): any {
	try {
		// eslint-disable-next-line @typescript-eslint/no-var-requires
		return require('findhit-proxywrap').proxy;
	} catch (e) {
		throw new Error(
			'Proxy protocol support requires the optional dependency ' +
				'"findhit-proxywrap". Install it with `npm install findhit-proxywrap`.'
		);
	}
}

function getProxyTransport(): any {
	if (!_proxyTransport) {
		_proxyTransport = loadProxy()(net, { strict: false, ignoreStrictExceptions: true });
	}
	return _proxyTransport;
}

function getProxyTlsTransport(): any {
	if (!_proxyTlsTransport) {
		_proxyTlsTransport = loadProxy()(tls, { strict: false, ignoreStrictExceptions: true });
	}
	return _proxyTlsTransport;
}

export interface SessionOptions {
	socket?: any;
	tls?: boolean;
	host?: string;
	port?: number;
	url?: string;
	debug?: boolean;
	debugListener?: ((type: any, msg: any, payload: any) => void) | null;
	connectTimeout?: number;
	auto_enquire_link_period?: number;
	rejectUnauthorized?: boolean;
	[key: string]: any;
}

export interface Session extends EventEmitter {
	// command shortcut methods (bind_transceiver, submit_sm, etc.) are attached dynamically
	[command: string]: any;
}

export function Session(this: any, options?: SessionOptions) {
	EventEmitter.call(this);
	this.options = options || {};
	var self = this;
	var clientTransport: any = net;
	var connectTimeout: any;
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
	this._id = Math.floor(Math.random() * (999999 - 100000)) + 100000; // random session id
	this._prevBytesRead = 0;
	this.rootSocket = function () {
		if (self.socket._parent) return self.socket._parent;
		return self.socket;
	};
	if (options && options.socket) {
		// server mode / socket is already connected.
		this._mode = 'server';
		this.socket = options.socket;
		this.remoteAddress = self.rootSocket().remoteAddress || self.remoteAddress;
		this.remotePort = this.rootSocket().remotePort;
		this.proxyProtocolProxy = this.rootSocket().proxyAddress
			? { address: this.rootSocket().proxyAddress, port: this.rootSocket().proxyPort }
			: false;
	} else {
		// client mode
		this._mode = 'client';
		options = options || {};
		if (options.tls) {
			clientTransport = tls;
		}
		if (
			options.hasOwnProperty('connectTimeout') &&
			(options.connectTimeout as number) > 0
		) {
			connectTimeout = setTimeout(function () {
				if (self.socket) {
					var e: any = new Error(
						'Timeout of ' +
							options!.connectTimeout +
							'ms while connecting to ' +
							self.options.host +
							':' +
							self.options.port
					);
					e.code = 'ETIMEOUT';
					e.timeout = options!.connectTimeout;
					self.socket.destroy(e);
				}
			}, options.connectTimeout);
		}
		this.socket = clientTransport.connect(this.options);
		this.socket.on(
			'connect',
			function () {
				clearTimeout(connectTimeout);
				self.remoteAddress = self.rootSocket().remoteAddress || self.remoteAddress;
				self.remotePort = self.rootSocket().remotePort || self.remoteAddress;
				self.debug('server.connected', 'connected to server', { secure: options!.tls });
				self.emitMetric('server.connected', 1);
				self.emit('connect'); // @todo should emit the session, but it would break BC
				if (self.options.auto_enquire_link_period) {
					self._interval = setInterval(function () {
						self.enquire_link();
					}, self.options.auto_enquire_link_period);
				}
			}.bind(this)
		);
		this.socket.on(
			'secureConnect',
			function () {
				self.emit('secureConnect'); // @todo should emit the session, but it would break BC
			}.bind(this)
		);
	}
	this.socket.on('readable', function () {
		var bytesRead = self.socket.bytesRead - self._prevBytesRead;
		if (bytesRead > 0) {
			// on disconnections the readable event receives 0 bytes, we do not want to debug that
			self.debug('socket.data.in', null, { bytes: bytesRead });
			self.emitMetric('socket.data.in', bytesRead, { bytes: bytesRead });
			self._prevBytesRead = self.socket.bytesRead;
		}
		self._extractPDUs();
	});
	this.socket.on('close', function () {
		self.closed = true;
		clearTimeout(connectTimeout);
		if (self._mode === 'server') {
			self.debug('client.disconnected', 'client has disconnected');
			self.emitMetric('client.disconnected', 1);
		} else {
			self.debug('server.disconnected', 'disconnected from server');
			self.emitMetric('server.disconnected', 1);
		}
		self.emit('close');
		if (self._interval) {
			clearInterval(self._interval);
			self._interval = 0;
		}
	});
	this.socket.on('error', function (e: any) {
		clearTimeout(connectTimeout);
		if (self._interval) {
			clearInterval(self._interval);
			self._interval = 0;
		}
		self.debug('socket.error', e.message, e);
		self.emitMetric('socket.error', 1, { error: e });
		self.emit('error', e); // Emitted errors will kill the program if they're not captured.
	});
}

util.inherits(Session, EventEmitter);

Session.prototype.emitMetric = function (event: any, value: any, payload: any) {
	this.emit('metrics', event || null, value || null, payload || {}, {
		mode: this._mode || null,
		remoteAddress: this.remoteAddress || null,
		remotePort: this.remotePort || null,
		remoteTls: this.options.tls || false,
		sessionId: this._id || null,
		session: this,
	});
};

Session.prototype.debug = function (type: any, msg: any, payload: any) {
	if (type === undefined) type = null;
	if (msg === undefined) msg = null;
	if (this.options.debug) {
		var coloredTypes: Record<string, string> = {
			reset: '\x1b[0m',
			dim: '\x1b[2m',
			'client.connected': '\x1b[1m\x1b[34m',
			'client.disconnected': '\x1b[1m\x1b[31m',
			'server.connected': '\x1b[1m\x1b[34m',
			'server.disconnected': '\x1b[1m\x1b[31m',
			'pdu.command.in': '\x1b[36m',
			'pdu.command.out': '\x1b[32m',
			'pdu.command.error': '\x1b[41m\x1b[30m',
			'socket.error': '\x1b[41m\x1b[30m',
			'socket.data.in': '\x1b[2m',
			'socket.data.out': '\x1b[2m',
			metrics: '\x1b[2m',
		};
		var now = new Date();
		var logBuffer =
			now.toISOString() +
			' - ' +
			(this._mode === 'server' ? 'srv' : 'cli') +
			' - ' +
			this._id +
			' - ' +
			(coloredTypes.hasOwnProperty(type)
				? coloredTypes[type] + type + coloredTypes.reset
				: type) +
			' - ' +
			(msg !== null ? msg : '') +
			' - ' +
			coloredTypes.dim +
			(payload !== undefined ? JSON.stringify(payload) : '') +
			coloredTypes.reset;
		if (this.remoteAddress) logBuffer += ' - [' + this.remoteAddress + ']';
		console.log(logBuffer);
	}
	if (this.options.debugListener instanceof Function) {
		this.options.debugListener(type, msg, payload);
	}
	this.emit('debug', type, msg, payload);
};

Session.prototype.connect = function () {
	this.sequence = 0;
	this.paused = false;
	this._busy = false;
	this._callbacks = {};
	this.socket.connect(this.options);
};

Session.prototype._extractPDUs = function () {
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
			this.debug('pdu.command.in', pdu.command, pdu);
			this.emitMetric('pdu.command.in', 1, pdu);
		} catch (e: any) {
			this.debug('pdu.command.error', e.message, e);
			this.emitMetric('pdu.command.error', 1, { error: e });
			this.emit('error', e);
			return;
		}
		this._command_length = null;
		this.emit('pdu', pdu);
		this.emit(pdu.command, pdu);
		if (pdu.isResponse() && this._callbacks[pdu.sequence_number]) {
			this._callbacks[pdu.sequence_number](pdu);
			delete this._callbacks[pdu.sequence_number];
		}
	}
	this._busy = false;
};

Session.prototype.send = function (
	pdu: any,
	responseCallback?: any,
	sendCallback?: any,
	failureCallback?: any
) {
	if (!this.socket.writable) {
		var errorObject = {
			error: 'Socket is not writable',
			errorType: 'socket_not_writable',
		};
		this.debug('socket.data.error', null, errorObject);
		this.emitMetric('socket.data.error', 1, errorObject);
		if (failureCallback) {
			pdu.command_status = defs.errors.ESME_RSUBMITFAIL;
			failureCallback(pdu);
		}
		return false;
	}
	if (!pdu.isResponse()) {
		// when server/session pair is used to proxy smpp
		// traffic, the sequence_number will be provided by
		// client otherwise we generate it automatically
		if (!pdu.sequence_number) {
			if (this.sequence == 0x7fffffff) {
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
	this.debug('pdu.command.out', pdu.command, pdu);
	this.emitMetric('pdu.command.out', 1, pdu);
	var buffer = pdu.toBuffer();
	this.socket.write(
		buffer,
		function (this: any, err: any) {
			if (err) {
				this.debug('socket.data.error', null, {
					error: 'Cannot write command ' + pdu.command + ' to socket',
					errorType: 'socket_write_error',
				});
				this.emitMetric('socket.data.error', 1, {
					error: err,
					errorType: 'socket_write_error',
					pdu: pdu,
				});
				if (!pdu.isResponse() && this._callbacks[pdu.sequence_number]) {
					delete this._callbacks[pdu.sequence_number];
				}
				if (failureCallback) {
					pdu.command_status = defs.errors.ESME_RSUBMITFAIL;
					failureCallback(pdu, err);
				}
			} else {
				this.debug('socket.data.out', null, { bytes: buffer.length, error: err });
				this.emitMetric('socket.data.out', buffer.length, { bytes: buffer.length });
				this.emit('send', pdu);
				if (sendCallback) {
					sendCallback(pdu);
				}
			}
		}.bind(this)
	);
	return true;
};

Session.prototype.pause = function () {
	this.paused = true;
};

Session.prototype.resume = function () {
	this.paused = false;
	this._extractPDUs();
};

Session.prototype.close = function (callback?: () => void) {
	if (callback) {
		if (this.closed) {
			callback();
		} else {
			this.socket.once('close', callback);
		}
	}
	this.socket.end();
};

Session.prototype.destroy = function (callback?: () => void) {
	if (callback) {
		if (this.closed) {
			callback();
		} else {
			this.socket.once('close', callback);
		}
	}
	this.socket.destroy();
};

var createShortcut = function (command: string) {
	return function (
		this: any,
		options?: any,
		responseCallback?: any,
		sendCallback?: any,
		failureCallback?: any
	) {
		if (typeof options == 'function') {
			sendCallback = responseCallback;
			responseCallback = options;
			options = {};
		}
		var pdu = new PDU(command, options);
		return this.send(pdu, responseCallback, sendCallback, failureCallback);
	};
};

for (var command in defs.commands) {
	Session.prototype[command] = createShortcut(command);
}

export interface ServerOptions {
	key?: string | Buffer;
	cert?: string | Buffer;
	debug?: boolean;
	debugListener?: ((type: any, msg: any, payload: any) => void) | null;
	isProxiedServer?: boolean;
	enable_proxy_protocol_detection?: boolean;
	autoPrependBuffer?: Buffer;
	tls?: boolean;
	[key: string]: any;
}

export function Server(this: any, options?: any, listener?: any) {
	var self = this,
		transport;
	this.sessions = [];
	this.isProxiedServer = options && options.isProxiedServer == true;

	if (typeof options == 'function') {
		listener = options;
		options = {};
	} else {
		options = options || {};
	}

	if (listener) {
		this.on('session', listener);
	}

	this.tls = options.key && options.cert;
	options.tls = this.tls != null; // standarized option for the session on both client & server
	this.options = options;

	self.on('proxiedConnection', function (socket: any) {
		// The connection has successfully passed through the proxied server (event emitted by proxywrap)
		socket.proxiedConnection = true;
	});

	// Fetch the right transport based on the current options
	if (this.isProxiedServer) {
		transport = this.tls ? getProxyTlsTransport() : getProxyTransport();
	} else {
		transport = this.tls ? tls : net;
	}
	transport.Server.call(this, options, function (socket: any) {
		var session: any = new (Session as any)({
			socket: socket,
			tls: self.options.tls,
			debug: self.options.debug,
			debugListener: self.options.debugListener || null,
		});
		session.server = self;
		if (socket.savedEmit) {
			// Restore the saved emit to fix the proxywrap bug (on nodejs <=8)
			socket.emit = socket.savedEmit;
			socket.savedEmit = null;
		}
		session.debug('client.connected', 'client has connected', {
			secure: self.options.tls,
			// Useful information for Proxy protocol debugging & testing
			proxiedServer: self.isProxiedServer,
			proxiedConnection:
				socket.proxiedConnection ||
				(socket._parent ? socket._parent.proxiedConnection : false) ||
				false,
			remoteAddress: session.remoteAddress,
			remotePort: session.remotePort,
			proxyProtocolProxy: session.proxyProtocolProxy,
		});
		self.sessions.push(session);
		socket.on('close', function () {
			self.sessions.splice(self.sessions.indexOf(session), 1);
		});
		self.emit('session', session);
		session.emitMetric('client.connected', 1);
	});

	if (this.isProxiedServer) {
		// The proxied wrapper clears all connection listeners and adds their own.
		// A new listener is added in order to catch socket error on the wrapper.
		self.on('connection', function (socket: any) {
			socket.on('error', function (e: any) {
				self.emit('error', e);
			});
			if (self.options.autoPrependBuffer) {
				// Allows to automatically prepend a buffer on the client socket. This feature is intended only for
				// testing purposes and it's used to inject client simulated headers (Proxy protocol)
				socket.unshift(self.options.autoPrependBuffer);
			}
			// There's a bug in the proxywrap server which tampers the emit method in nodejs <= 8 and makes the
			// socket unable to emit the events. As a simple fix, save the emit method so it can be restored later.
			socket.savedEmit = socket.emit;
		});
	}
}

export function SecureServer(this: any, options?: any, listener?: any) {
	Server.call(this, options, listener);
}

// Standard servers without proxy protocol support
util.inherits(Server, net.Server);
util.inherits(SecureServer, tls.Server);

// Proxy-protocol server constructors are built lazily so the optional
// `findhit-proxywrap` dependency (and its GPLv3 transitive dep) is only
// required when proxy protocol detection is actually enabled (issue #214).
let _ProxyServer: any = null;
let _ProxySecureServer: any = null;

function getProxyServer(): any {
	if (!_ProxyServer) {
		_ProxyServer = function (this: any, options: any, listener?: any) {
			options.isProxiedServer = true;
			Server.call(this, options, listener);
		};
		util.inherits(_ProxyServer, getProxyTransport().Server);
	}
	return _ProxyServer;
}

function getProxySecureServer(): any {
	if (!_ProxySecureServer) {
		_ProxySecureServer = function (this: any, options: any, listener?: any) {
			options.isProxiedServer = true;
			Server.call(this, options, listener);
		};
		util.inherits(_ProxySecureServer, getProxyTlsTransport().Server);
	}
	return _ProxySecureServer;
}

export function createServer(options?: any, listener?: any) {
	if (typeof options == 'function') {
		listener = options;
		options = {};
	} else {
		options = options || {};
	}

	if (options.key && options.cert) {
		if (options.enable_proxy_protocol_detection) {
			return new (getProxySecureServer())(options, listener);
		} else {
			return new (SecureServer as any)(options, listener);
		}
	} else {
		if (options.enable_proxy_protocol_detection) {
			return new (getProxyServer())(options, listener);
		} else {
			return new (Server as any)(options, listener);
		}
	}
}

export function connect(options?: any, listener?: any): any {
	var clientOptions: any = {};

	if (arguments.length > 1 && typeof listener != 'function') {
		clientOptions = {
			host: options,
			port: listener,
		};
		listener = arguments[3];
	} else if (typeof options == 'string') {
		clientOptions = parse(options);
		clientOptions.host = clientOptions.slashes ? clientOptions.hostname : options;
		clientOptions.tls = clientOptions.protocol === 'ssmpp:';
	} else if (typeof options == 'function') {
		listener = options;
	} else {
		clientOptions = options || {};
		if (clientOptions.url) {
			options = parse(clientOptions.url);
			clientOptions.host = options.hostname;
			clientOptions.port = options.port;
			clientOptions.tls = options.protocol === 'ssmpp:';
		}
	}
	if (clientOptions.tls && !clientOptions.hasOwnProperty('rejectUnauthorized')) {
		clientOptions.rejectUnauthorized = false; // Allow self signed certificates by default
	}
	clientOptions.port = clientOptions.port || (clientOptions.tls ? 3550 : 2775);
	clientOptions.debug = clientOptions.debug || false;
	clientOptions.connectTimeout = clientOptions.connectTimeout || 30000;

	var session: any = new (Session as any)(clientOptions);
	if (listener) {
		session.on(clientOptions.tls ? 'secureConnect' : 'connect', function () {
			listener(session);
		});
	}

	return session;
}

export const createSession = connect;

export function addCommand(command: string, options: any) {
	options.command = command;
	defs.commands[command] = options;
	defs.commandsById[options.id] = options;
	Session.prototype[command] = createShortcut(command);
}

export function addTLV(tag: string, options: any) {
	options.tag = tag;
	defs.tlvs[tag] = options;
	defs.tlvsById[options.id] = options;
}

export { PDU };

// Re-export everything from defs (consts, commands, types, tlvs, gsmCoder,
// filters, encodings, errors)
export * from './defs';

// Flatten consts groups onto the module namespace for backward compatibility
// (e.g. smpp.TON, smpp.NPI, smpp.ENCODING ...)
export const {
	REGISTERED_DELIVERY,
	ESM_CLASS,
	MESSAGE_STATE,
	TON,
	NPI,
	ENCODING,
	NETWORK,
	BROADCAST_AREA_FORMAT,
	BROADCAST_FREQUENCY_INTERVAL,
} = defs.consts;

// Flatten error codes onto the module namespace for backward compatibility
// (e.g. smpp.ESME_ROK, smpp.ESME_RSUBMITFAIL ...)
export const {
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
	ESME_RINVBCASTCHANIND,
} = defs.errors;
