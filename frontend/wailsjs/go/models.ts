export namespace main {
	
	export class AppConfig {
	    EnableGov: boolean;
	    EnableBlack: boolean;
	    EnableWhite: boolean;
	    EnableDedup: boolean;
	    EnableKeyword: boolean;
	    RemoveProto: boolean;
	    EnableStatus: boolean;
	    Keyword: string;
	    AllowedCodes: Record<number, boolean>;
	    Timeout: number;
	    Threads: number;
	    BlackDomains: string[];
	    WhiteDomains: string[];
	
	    static createFrom(source: any = {}) {
	        return new AppConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.EnableGov = source["EnableGov"];
	        this.EnableBlack = source["EnableBlack"];
	        this.EnableWhite = source["EnableWhite"];
	        this.EnableDedup = source["EnableDedup"];
	        this.EnableKeyword = source["EnableKeyword"];
	        this.RemoveProto = source["RemoveProto"];
	        this.EnableStatus = source["EnableStatus"];
	        this.Keyword = source["Keyword"];
	        this.AllowedCodes = source["AllowedCodes"];
	        this.Timeout = source["Timeout"];
	        this.Threads = source["Threads"];
	        this.BlackDomains = source["BlackDomains"];
	        this.WhiteDomains = source["WhiteDomains"];
	    }
	}
	export class AssetExtractionResult {
	    URLs: string[];
	    RootDomains: string[];
	    IPs: string[];
	    CNetworks: string[];
	    Other: string[];
	
	    static createFrom(source: any = {}) {
	        return new AssetExtractionResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.URLs = source["URLs"];
	        this.RootDomains = source["RootDomains"];
	        this.IPs = source["IPs"];
	        this.CNetworks = source["CNetworks"];
	        this.Other = source["Other"];
	    }
	}
	export class Counters {
	    Total: number;
	    Keep: number;
	    Gov: number;
	    Black: number;
	    White: number;
	    KeyBlock: number;
	    StatusBlock: number;
	    Dup: number;
	    Invalid: number;
	
	    static createFrom(source: any = {}) {
	        return new Counters(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Total = source["Total"];
	        this.Keep = source["Keep"];
	        this.Gov = source["Gov"];
	        this.Black = source["Black"];
	        this.White = source["White"];
	        this.KeyBlock = source["KeyBlock"];
	        this.StatusBlock = source["StatusBlock"];
	        this.Dup = source["Dup"];
	        this.Invalid = source["Invalid"];
	    }
	}
	export class ProcessOptions {
	    EnableGov: boolean;
	    EnableBlack: boolean;
	    EnableWhite: boolean;
	    EnableDedup: boolean;
	    EnableKeyword: boolean;
	    RemoveProto: boolean;
	    EnableStatus: boolean;
	    Keyword: string;
	    AllowedCodes: Record<number, boolean>;
	    Timeout: number;
	    Threads: number;
	    BlackDomains: Record<string, boolean>;
	    WhiteDomains: Record<string, boolean>;
	
	    static createFrom(source: any = {}) {
	        return new ProcessOptions(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.EnableGov = source["EnableGov"];
	        this.EnableBlack = source["EnableBlack"];
	        this.EnableWhite = source["EnableWhite"];
	        this.EnableDedup = source["EnableDedup"];
	        this.EnableKeyword = source["EnableKeyword"];
	        this.RemoveProto = source["RemoveProto"];
	        this.EnableStatus = source["EnableStatus"];
	        this.Keyword = source["Keyword"];
	        this.AllowedCodes = source["AllowedCodes"];
	        this.Timeout = source["Timeout"];
	        this.Threads = source["Threads"];
	        this.BlackDomains = source["BlackDomains"];
	        this.WhiteDomains = source["WhiteDomains"];
	    }
	}
	export class ProcessResult {
	    Results: string[];
	    Logs: string[];
	    Counters?: Counters;
	    Canceled: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ProcessResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Results = source["Results"];
	        this.Logs = source["Logs"];
	        this.Counters = this.convertValues(source["Counters"], Counters);
	        this.Canceled = source["Canceled"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ProcessingState {
	    Active: boolean;
	    Paused: boolean;
	    CancelRequested: boolean;
	    Finished: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ProcessingState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Active = source["Active"];
	        this.Paused = source["Paused"];
	        this.CancelRequested = source["CancelRequested"];
	        this.Finished = source["Finished"];
	    }
	}

}

