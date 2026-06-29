import {
	commands,
	commandsById,
	tlvs,
	tlvsById,
	errors,
} from './defs';

const pduHeadParams = [
	'command_length',
	'command_id',
	'command_status',
	'sequence_number',
];

// A user-defined / unknown TLV is addressed by its numeric tag id (e.g. 0x3C02)
// which becomes a numeric-string key on the PDU. Treat such keys as raw TLVs so
// they round-trip on encode, not only on decode (issue #231).
function isRawTlvKey(key: string, params: Record<string, any>): boolean {
	if (!/^[0-9]+$/.test(key)) return false;
	var id = Number(key);
	if (id < 0 || id > 0xffff) return false;
	return !(key in params) && !tlvs[key];
}

function toRawTlvBuffer(value: any): Buffer {
	if (Buffer.isBuffer(value)) return value;
	if (value === null || value === undefined) return Buffer.alloc(0);
	return Buffer.from(String(value), 'ascii');
}

export interface PDUOptions {
	command_status?: number;
	sequence_number?: number;
	[key: string]: any;
}

export class PDU {
	static maxLength = 16384;

	command!: string;
	command_length!: number;
	command_id!: number;
	command_status!: number;
	sequence_number!: number;
	[key: string]: any;

	constructor(command: Buffer | string, options?: PDUOptions) {
		if (Buffer.isBuffer(command)) {
			return this.fromBuffer(command) as any;
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
			} else if ('default' in params[key]) {
				this[key] = params[key].default;
			} else {
				this[key] = params[key].type.default;
			}
		}
		for (var key in options)
			if (key in tlvs && !(key in params)) {
				this[key] = options[key];
			}
		// user-defined / unknown TLVs addressed by numeric tag id (issue #231)
		for (var rkey in options)
			if (isRawTlvKey(rkey, params)) {
				this[rkey] = options[rkey];
			}
	}

	static commandLength(stream: { read(size: number): Buffer | null }): number | false {
		var buffer = stream.read(4);
		if (!buffer) {
			return false;
		}
		var command_length = buffer.readUInt32BE(0);
		if (command_length > PDU.maxLength) {
			throw Error(
				'PDU length was too large (' +
					command_length +
					', maximum is ' +
					PDU.maxLength +
					').'
			);
		}
		return command_length;
	}

	static fromStream(
		stream: { read(size: number): Buffer | null },
		command_length: number
	): PDU | false {
		var buffer = stream.read(command_length - 4);
		if (!buffer) {
			return false;
		}
		var commandLengthBuffer = Buffer.alloc(4);
		commandLengthBuffer.writeUInt32BE(command_length, 0);
		var pduBuffer = Buffer.concat([commandLengthBuffer, buffer]);

		return new PDU(pduBuffer);
	}

	static fromBuffer(buffer: Buffer): PDU | false {
		if (buffer.length < 16 || buffer.length < buffer.readUInt32BE(0)) {
			return false;
		}
		return new PDU(buffer);
	}

	isResponse(): boolean {
		return !!(this.command_id & 0x80000000);
	}

	response(options?: PDUOptions): PDU {
		options = options || {};
		options.sequence_number = this.sequence_number;
		if (this.command == 'unknown') {
			if (!('command_status' in options)) {
				options.command_status = errors.ESME_RINVCMDID;
			}
			return new PDU('generic_nack', options);
		}
		return new PDU(this.command + '_resp', options);
	}

	fromBuffer(buffer: Buffer): this {
		pduHeadParams.forEach(
			function (this: any, key: string, i: number) {
				this[key] = buffer.readUInt32BE(i * 4);
			}.bind(this)
		);
		// Since each pduHeaderParam is 4 bytes/octets, the offset is equal to the total length of the
		// pduHeadParams*4, its better to use that basis for maintenance.
		var params,
			offset = pduHeadParams.length * 4;
		if (this.command_length > PDU.maxLength) {
			throw Error(
				'PDU length was too large (' +
					this.command_length +
					', maximum is ' +
					PDU.maxLength +
					').'
			);
		}
		if (commandsById[this.command_id]) {
			this.command = commandsById[this.command_id].command!;
			params = commands[this.command].params || {};
		} else {
			this.command = 'unknown';
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
			var tag = (commands[this.command].tlvMap || {})[tlv.tag!] || tlv.tag!;
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
		this._filter('decode');
		return this;
	}

	_filter(func: 'encode' | 'decode'): void {
		var self: any = this;
		var params = commands[this.command].params || {};
		for (var key in self) {
			if (params[key] && params[key].filter) {
				self[key] = params[key].filter![func].call(self, self[key]);
			} else if (tlvs[key] && tlvs[key].filter) {
				if (tlvs[key].multiple) {
					self[key].forEach(function (value: any, i: number) {
						self[key][i] = tlvs[key].filter![func].call(self, value, true);
					});
				} else {
					if (key === 'message_payload') {
						var skipUdh =
							self.short_message &&
							self.short_message.message &&
							self.short_message.message.length;
						self[key] = tlvs[key].filter![func].call(self, self[key], skipUdh);
					} else {
						self[key] = tlvs[key].filter![func].call(self, self[key], true);
					}
				}
			}
		}
	}

	_initBuffer(): Buffer {
		var buffer = Buffer.alloc(this.command_length);
		pduHeadParams.forEach(
			function (this: any, key: string, i: number) {
				buffer.writeUInt32BE(this[key], i * 4);
			}.bind(this)
		);
		return buffer;
	}

	toBuffer(): Buffer {
		// Since each pduHeaderParam is 4 bytes/octets, the offset is equal to the total length of the
		// pduHeadParams*4, its better to use that basis for maintainance.
		this.command_length = pduHeadParams.length * 4;
		if (this.command_status) {
			return this._initBuffer();
		}
		this._filter('encode');
		var self: any = this;
		var params = commands[this.command].params || {};
		for (var key in self) {
			if (params[key]) {
				this.command_length += params[key].type.size(self[key]);
			} else if (tlvs[key]) {
				var values = tlvs[key].multiple ? self[key] : [self[key]];
				values.forEach((value: any) => {
					this.command_length += tlvs[key].type.size(value) + 4;
				});
			} else if (isRawTlvKey(key, params)) {
				// User-defined / unknown TLV addressed by its numeric tag id
				// (issue #231). Value is a Buffer or string, written verbatim.
				this.command_length += toRawTlvBuffer(self[key]).length + 4;
			}
		}
		var buffer = this._initBuffer();
		// Since each pduHeaderParam is 4 bytes/octets, the offset is equal to the total length of the
		// pduHeadParams*4, its better to use that basis for maintainance.
		var offset = pduHeadParams.length * 4;
		for (var pkey in params) {
			params[pkey].type.write(self[pkey], buffer, offset);
			offset += params[pkey].type.size(self[pkey]);
		}
		for (var key in self)
			if (tlvs[key] && !(key in params)) {
				var values = tlvs[key].multiple ? self[key] : [self[key]];
				values.forEach(function (value: any) {
					buffer.writeUInt16BE(tlvs[key].id, offset);
					var length = tlvs[key].type.size(value);
					buffer.writeUInt16BE(length, offset + 2);
					offset += 4;
					tlvs[key].type.write(value, buffer, offset);
					offset += length;
				});
			}
		for (var rkey in self)
			if (isRawTlvKey(rkey, params)) {
				var raw = toRawTlvBuffer(self[rkey]);
				buffer.writeUInt16BE(Number(rkey), offset);
				buffer.writeUInt16BE(raw.length, offset + 2);
				offset += 4;
				raw.copy(buffer, offset);
				offset += raw.length;
			}
		return buffer;
	}
}
