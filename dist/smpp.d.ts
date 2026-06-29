import { EventEmitter } from 'events';

interface PDUOptions {
    command_status?: number;
    sequence_number?: number;
    [key: string]: any;
}
declare class PDU {
    static maxLength: number;
    command: string;
    command_length: number;
    command_id: number;
    command_status: number;
    sequence_number: number;
    [key: string]: any;
    constructor(command: Buffer | string, options?: PDUOptions);
    static commandLength(stream: {
        read(size: number): Buffer | null;
    }): number | false;
    static fromStream(stream: {
        read(size: number): Buffer | null;
    }, command_length: number): PDU | false;
    static fromBuffer(buffer: Buffer): PDU | false;
    isResponse(): boolean;
    response(options?: PDUOptions): PDU;
    fromBuffer(buffer: Buffer): this;
    _filter(func: 'encode' | 'decode'): void;
    _initBuffer(): Buffer;
    toBuffer(): Buffer;
}

interface Codec<T = any> {
    read(buffer: Buffer, offset: number, length?: number): T;
    write(value: T, buffer: Buffer, offset: number): void;
    size(value?: T): number;
    default: T;
}
interface Filter {
    encode(this: any, value: any, ...rest: any[]): any;
    decode(this: any, value: any, ...rest: any[]): any;
}
interface ParamDef {
    type: Codec;
    default?: any;
    filter?: Filter;
}
interface CommandDef {
    id: number;
    command?: string;
    params?: Record<string, ParamDef>;
    tlvMap?: Record<string, string>;
}
interface TlvDef {
    id: number;
    tag?: string;
    type: Codec;
    filter?: Filter;
    multiple?: boolean;
}
interface Encoding {
    match(value: string): boolean;
    encode(value: string): Buffer;
    decode(value: Buffer): string;
}
interface TypesMap {
    int8: Codec<number>;
    int16: Codec<number>;
    int32: Codec<number>;
    string: Codec<any>;
    cstring: Codec<any>;
    buffer: Codec<any>;
    dest_address_array: Codec<any[]>;
    unsuccess_sme_array: Codec<any[]>;
    tlv: {
        int8: Codec<number>;
        int16: Codec<number>;
        int32: Codec<number>;
        cstring: Codec<any>;
        string: Codec<any>;
        buffer: Codec<any>;
    };
}
declare const types: TypesMap;
interface GsmTable {
    chars: string;
    extChars?: string;
    escChars?: string;
    extCharsEnc?: string;
    escCharsEnc?: string;
    extCharsDec?: string;
    escCharsDec?: string;
    charRegex: RegExp;
    charListEnc: Record<string, number>;
    extCharListEnc: Record<string, string>;
    charListDec: Record<number, string>;
    extCharListDec: Record<string, string>;
}
declare const gsmCoder: {
    GSM: GsmTable;
    GSM_TR: GsmTable;
    GSM_ES: GsmTable;
    GSM_PT: GsmTable;
    getCoder(encoding?: number): GsmTable;
    encode(string: string, encoding?: number): Buffer;
    decode(string: Buffer | number[], encoding?: number): string;
    detect(string: string): number | undefined;
};
declare const encodings: Record<string, Encoding> & {
    detect(value: string): string | false;
    default: string;
};
declare const filters: Record<string, Filter>;
declare const tlvs: Record<string, TlvDef>;
declare const tlvsById: Record<number, TlvDef>;
declare const commands: Record<string, CommandDef>;
declare const commandsById: Record<number, CommandDef>;
declare const consts: {
    REGISTERED_DELIVERY: {
        FINAL: number;
        FAILURE: number;
        SUCCESS: number;
        DELIVERY_ACKNOWLEDGEMENT: number;
        USER_ACKNOWLEDGEMENT: number;
        INTERMEDIATE: number;
    };
    ESM_CLASS: {
        DATAGRAM: number;
        FORWARD: number;
        STORE_FORWARD: number;
        MC_DELIVERY_RECEIPT: number;
        DELIVERY_ACKNOWLEDGEMENT: number;
        USER_ACKNOWLEDGEMENT: number;
        CONVERSATION_ABORT: number;
        INTERMEDIATE_DELIVERY: number;
        UDH_INDICATOR: number;
        KANNEL_UDH_INDICATOR: number;
        SET_REPLY_PATH: number;
    };
    MESSAGE_STATE: {
        SCHEDULED: number;
        ENROUTE: number;
        DELIVERED: number;
        EXPIRED: number;
        DELETED: number;
        UNDELIVERABLE: number;
        ACCEPTED: number;
        UNKNOWN: number;
        REJECTED: number;
        SKIPPED: number;
    };
    TON: {
        UNKNOWN: number;
        INTERNATIONAL: number;
        NATIONAL: number;
        NETWORK_SPECIFIC: number;
        SUBSCRIBER_NUMBER: number;
        ALPHANUMERIC: number;
        ABBREVIATED: number;
    };
    NPI: {
        UNKNOWN: number;
        ISDN: number;
        DATA: number;
        TELEX: number;
        LAND_MOBILE: number;
        NATIONAL: number;
        PRIVATE: number;
        ERMES: number;
        INTERNET: number;
        IP: number;
        WAP: number;
    };
    ENCODING: {
        SMSC_DEFAULT: number;
        ASCII: number;
        GSM_TR: number;
        GSM_ES: number;
        GSM_PT: number;
        IA5: number;
        LATIN1: number;
        ISO_8859_1: number;
        BINARY: number;
        JIS: number;
        X_0208_1990: number;
        CYRILLIC: number;
        ISO_8859_5: number;
        HEBREW: number;
        ISO_8859_8: number;
        UCS2: number;
        PICTOGRAM: number;
        ISO_2022_JP: number;
        EXTENDED_KANJI_JIS: number;
        X_0212_1990: number;
        KS_C_5601: number;
    };
    NETWORK: {
        GENERIC: number;
        GSM: number;
        TDMA: number;
        CDMA: number;
    };
    BROADCAST_AREA_FORMAT: {
        NAME: number;
        ALIAS: number;
        ELLIPSOID_ARC: number;
        POLYGON: number;
    };
    BROADCAST_FREQUENCY_INTERVAL: {
        MAX_POSSIBLE: number;
        SECONDS: number;
        MINUTES: number;
        HOURS: number;
        DAYS: number;
        WEEKS: number;
        MONTHS: number;
        YEARS: number;
    };
};
declare const errors: Record<string, number>;

interface SessionOptions {
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
interface Session extends EventEmitter {
    [command: string]: any;
}
declare function Session(this: any, options?: SessionOptions): void;
interface ServerOptions {
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
declare function Server(this: any, options?: any, listener?: any): void;
declare function SecureServer(this: any, options?: any, listener?: any): void;
declare function createServer(options?: any, listener?: any): any;
declare function connect(options?: any, listener?: any): any;
declare const createSession: typeof connect;
declare function addCommand(command: string, options: any): void;
declare function addTLV(tag: string, options: any): void;

declare const REGISTERED_DELIVERY: {
    FINAL: number;
    FAILURE: number;
    SUCCESS: number;
    DELIVERY_ACKNOWLEDGEMENT: number;
    USER_ACKNOWLEDGEMENT: number;
    INTERMEDIATE: number;
};
declare const ESM_CLASS: {
    DATAGRAM: number;
    FORWARD: number;
    STORE_FORWARD: number;
    MC_DELIVERY_RECEIPT: number;
    DELIVERY_ACKNOWLEDGEMENT: number;
    USER_ACKNOWLEDGEMENT: number;
    CONVERSATION_ABORT: number;
    INTERMEDIATE_DELIVERY: number;
    UDH_INDICATOR: number;
    KANNEL_UDH_INDICATOR: number;
    SET_REPLY_PATH: number;
};
declare const MESSAGE_STATE: {
    SCHEDULED: number;
    ENROUTE: number;
    DELIVERED: number;
    EXPIRED: number;
    DELETED: number;
    UNDELIVERABLE: number;
    ACCEPTED: number;
    UNKNOWN: number;
    REJECTED: number;
    SKIPPED: number;
};
declare const TON: {
    UNKNOWN: number;
    INTERNATIONAL: number;
    NATIONAL: number;
    NETWORK_SPECIFIC: number;
    SUBSCRIBER_NUMBER: number;
    ALPHANUMERIC: number;
    ABBREVIATED: number;
};
declare const NPI: {
    UNKNOWN: number;
    ISDN: number;
    DATA: number;
    TELEX: number;
    LAND_MOBILE: number;
    NATIONAL: number;
    PRIVATE: number;
    ERMES: number;
    INTERNET: number;
    IP: number;
    WAP: number;
};
declare const ENCODING: {
    SMSC_DEFAULT: number;
    ASCII: number;
    GSM_TR: number;
    GSM_ES: number;
    GSM_PT: number;
    IA5: number;
    LATIN1: number;
    ISO_8859_1: number;
    BINARY: number;
    JIS: number;
    X_0208_1990: number;
    CYRILLIC: number;
    ISO_8859_5: number;
    HEBREW: number;
    ISO_8859_8: number;
    UCS2: number;
    PICTOGRAM: number;
    ISO_2022_JP: number;
    EXTENDED_KANJI_JIS: number;
    X_0212_1990: number;
    KS_C_5601: number;
};
declare const NETWORK: {
    GENERIC: number;
    GSM: number;
    TDMA: number;
    CDMA: number;
};
declare const BROADCAST_AREA_FORMAT: {
    NAME: number;
    ALIAS: number;
    ELLIPSOID_ARC: number;
    POLYGON: number;
};
declare const BROADCAST_FREQUENCY_INTERVAL: {
    MAX_POSSIBLE: number;
    SECONDS: number;
    MINUTES: number;
    HOURS: number;
    DAYS: number;
    WEEKS: number;
    MONTHS: number;
    YEARS: number;
};
declare const ESME_ROK: number;
declare const ESME_RINVMSGLEN: number;
declare const ESME_RINVCMDLEN: number;
declare const ESME_RINVCMDID: number;
declare const ESME_RINVBNDSTS: number;
declare const ESME_RALYBND: number;
declare const ESME_RINVPRTFLG: number;
declare const ESME_RINVREGDLVFLG: number;
declare const ESME_RSYSERR: number;
declare const ESME_RINVSRCADR: number;
declare const ESME_RINVDSTADR: number;
declare const ESME_RINVMSGID: number;
declare const ESME_RBINDFAIL: number;
declare const ESME_RINVPASWD: number;
declare const ESME_RINVSYSID: number;
declare const ESME_RCANCELFAIL: number;
declare const ESME_RREPLACEFAIL: number;
declare const ESME_RMSGQFUL: number;
declare const ESME_RINVSERTYP: number;
declare const ESME_RINVNUMDESTS: number;
declare const ESME_RINVDLNAME: number;
declare const ESME_RINVDESTFLAG: number;
declare const ESME_RINVSUBREP: number;
declare const ESME_RINVESMCLASS: number;
declare const ESME_RCNTSUBDL: number;
declare const ESME_RSUBMITFAIL: number;
declare const ESME_RINVSRCTON: number;
declare const ESME_RINVSRCNPI: number;
declare const ESME_RINVDSTTON: number;
declare const ESME_RINVDSTNPI: number;
declare const ESME_RINVSYSTYP: number;
declare const ESME_RINVREPFLAG: number;
declare const ESME_RINVNUMMSGS: number;
declare const ESME_RTHROTTLED: number;
declare const ESME_RINVSCHED: number;
declare const ESME_RINVEXPIRY: number;
declare const ESME_RINVDFTMSGID: number;
declare const ESME_RX_T_APPN: number;
declare const ESME_RX_P_APPN: number;
declare const ESME_RX_R_APPN: number;
declare const ESME_RQUERYFAIL: number;
declare const ESME_RINVTLVSTREAM: number;
declare const ESME_RTLVNOTALLWD: number;
declare const ESME_RINVTLVLEN: number;
declare const ESME_RMISSINGTLV: number;
declare const ESME_RINVTLVVAL: number;
declare const ESME_RDELIVERYFAILURE: number;
declare const ESME_RUNKNOWNERR: number;
declare const ESME_RSERTYPUNAUTH: number;
declare const ESME_RPROHIBITED: number;
declare const ESME_RSERTYPUNAVAIL: number;
declare const ESME_RSERTYPDENIED: number;
declare const ESME_RINVDCS: number;
declare const ESME_RINVSRCADDRSUBUNIT: number;
declare const ESME_RINVDSTADDRSUBUNIT: number;
declare const ESME_RINVBCASTFREQINT: number;
declare const ESME_RINVBCASTALIAS_NAME: number;
declare const ESME_RINVBCASTAREAFMT: number;
declare const ESME_RINVNUMBCAST_AREAS: number;
declare const ESME_RINVBCASTCNTTYPE: number;
declare const ESME_RINVBCASTMSGCLASS: number;
declare const ESME_RBCASTFAIL: number;
declare const ESME_RBCASTQUERYFAIL: number;
declare const ESME_RBCASTCANCELFAIL: number;
declare const ESME_RINVBCAST_REP: number;
declare const ESME_RINVBCASTSRVGRP: number;
declare const ESME_RINVBCASTCHANIND: number;

export { BROADCAST_AREA_FORMAT, BROADCAST_FREQUENCY_INTERVAL, type Codec, type CommandDef, ENCODING, ESME_RALYBND, ESME_RBCASTCANCELFAIL, ESME_RBCASTFAIL, ESME_RBCASTQUERYFAIL, ESME_RBINDFAIL, ESME_RCANCELFAIL, ESME_RCNTSUBDL, ESME_RDELIVERYFAILURE, ESME_RINVBCASTALIAS_NAME, ESME_RINVBCASTAREAFMT, ESME_RINVBCASTCHANIND, ESME_RINVBCASTCNTTYPE, ESME_RINVBCASTFREQINT, ESME_RINVBCASTMSGCLASS, ESME_RINVBCASTSRVGRP, ESME_RINVBCAST_REP, ESME_RINVBNDSTS, ESME_RINVCMDID, ESME_RINVCMDLEN, ESME_RINVDCS, ESME_RINVDESTFLAG, ESME_RINVDFTMSGID, ESME_RINVDLNAME, ESME_RINVDSTADDRSUBUNIT, ESME_RINVDSTADR, ESME_RINVDSTNPI, ESME_RINVDSTTON, ESME_RINVESMCLASS, ESME_RINVEXPIRY, ESME_RINVMSGID, ESME_RINVMSGLEN, ESME_RINVNUMBCAST_AREAS, ESME_RINVNUMDESTS, ESME_RINVNUMMSGS, ESME_RINVPASWD, ESME_RINVPRTFLG, ESME_RINVREGDLVFLG, ESME_RINVREPFLAG, ESME_RINVSCHED, ESME_RINVSERTYP, ESME_RINVSRCADDRSUBUNIT, ESME_RINVSRCADR, ESME_RINVSRCNPI, ESME_RINVSRCTON, ESME_RINVSUBREP, ESME_RINVSYSID, ESME_RINVSYSTYP, ESME_RINVTLVLEN, ESME_RINVTLVSTREAM, ESME_RINVTLVVAL, ESME_RMISSINGTLV, ESME_RMSGQFUL, ESME_ROK, ESME_RPROHIBITED, ESME_RQUERYFAIL, ESME_RREPLACEFAIL, ESME_RSERTYPDENIED, ESME_RSERTYPUNAUTH, ESME_RSERTYPUNAVAIL, ESME_RSUBMITFAIL, ESME_RSYSERR, ESME_RTHROTTLED, ESME_RTLVNOTALLWD, ESME_RUNKNOWNERR, ESME_RX_P_APPN, ESME_RX_R_APPN, ESME_RX_T_APPN, ESM_CLASS, type Encoding, type Filter, MESSAGE_STATE, NETWORK, NPI, PDU, type ParamDef, REGISTERED_DELIVERY, SecureServer, Server, type ServerOptions, Session, type SessionOptions, TON, type TlvDef, addCommand, addTLV, commands, commandsById, connect, consts, createServer, createSession, encodings, errors, filters, gsmCoder, tlvs, tlvsById, types };
