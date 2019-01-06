unit dnsapi;

interface

uses windows,sysutils,winsock;

const
  DNS_UPDATE_SECURITY_USE_DEFAULT = 0;
   DNS_UPDATE_SECURITY_OFF =$10;
   DNS_UPDATE_SECURITY_ON =$20;
   DNS_UPDATE_SECURITY_ONLY=$100;
//autres
  DNS_ATMA_MAX_ADDR_LENGTH = 20;
  DNS_ATMA_AESA_ADDR_LENGTH = 20;

  /// Various DNS record types
DNS_TYPE_A          = $0001;      //  1
DNS_TYPE_NS         = $0002;      //  2
DNS_TYPE_MD         = $0003;      //  3
DNS_TYPE_MF         = $0004;      //  4
DNS_TYPE_CNAME      = $0005;      //  5
DNS_TYPE_SOA        = $0006;      //  6
DNS_TYPE_MB         = $0007;      //  7
DNS_TYPE_MG         = $0008;      //  8
DNS_TYPE_MR         = $0009;      //  9
DNS_TYPE_NULL       = $000a;      //  10
DNS_TYPE_WKS        = $000b;      //  11
DNS_TYPE_PTR        = $000c;      //  12
DNS_TYPE_HINFO      = $000d;      //  13
DNS_TYPE_MINFO      = $000e;      //  14
DNS_TYPE_MX         = $000f;      //  15
DNS_TYPE_TEXT       = $0010;      //  16
DNS_TYPE_RP	= $0011;
DNS_TYPE_AFSDB	= $0012;
DNS_TYPE_X25	= $0013   ;
DNS_TYPE_ISDN	= $0014    ;
DNS_TYPE_RT	= $0015       ;
DNS_TYPE_NSAP	= $0016     ;
DNS_TYPE_NSAPPTR	= $0017 ;
DNS_TYPE_SIG	= $0018     ;
DNS_TYPE_KEY	= $0019     ;
DNS_TYPE_PX	= $001a       ;
DNS_TYPE_GPOS	= $001b     ;
DNS_TYPE_AAAA	= $001c     ;
DNS_TYPE_LOC	= $001d     ;
DNS_TYPE_NXT	= $001e     ;
DNS_TYPE_EID	= $001f     ;
DNS_TYPE_NIMLOC	= $0020   ;
DNS_TYPE_SRV	= $0021      ;
DNS_TYPE_ATMA	= $0022     ;
DNS_TYPE_NAPTR	= $0023   ;
DNS_TYPE_KX	= $0024       ;
DNS_TYPE_CERT	= $0025     ;
DNS_TYPE_A6	= $0026       ;
DNS_TYPE_DNAME	= $0027   ;
DNS_TYPE_SINK	= $0028     ;
DNS_TYPE_OPT	= $0029     ;
DNS_TYPE_DS	= $002B       ;
DNS_TYPE_RRSIG	= $002E   ;
DNS_TYPE_NSEC	= $002F     ;
DNS_TYPE_DNSKEY	= $0030   ;
DNS_TYPE_DHCID	= $0031   ;
DNS_TYPE_UINFO	= $0064   ;
DNS_TYPE_UID	= $0065     ;
DNS_TYPE_GID	= $0066     ;
DNS_TYPE_UNSPEC	= $0067   ;
DNS_TYPE_ADDRS	= $00f8   ;
DNS_TYPE_TKEY	= $00f9      ;
DNS_TYPE_TSIG	= $00fa      ;
DNS_TYPE_IXFR	= $00fb     ;
DNS_TYPE_AXFR	= $00fc     ;
DNS_TYPE_MAILB	= $00fd   ;
DNS_TYPE_MAILA	= $00fe   ;
DNS_TYPE_ALL	= $00ff      ;
DNS_TYPE_ANY	= $00ff     ;
DNS_TYPE_WINS	= $ff01     ;
DNS_TYPE_WINSR	= $ff02   ;
DNS_TYPE_NBSTAT=	DNS_TYPE_WINSR;

type
IP6_ADDRESS = array[0..3] of dword;
IP4_ADDRESS = DWORD;
  DNS_A_DATA = IP4_ADDRESS;
  DNS_PTR_DATA = PChar;
  DNS_PTR_DATAA = DNS_PTR_DATA;
  DNS_PTR_DATAW = DNS_PTR_DATA;
  DNS_AAAA_DATA = IP6_ADDRESS;
  DNS_STATUS = LongInt;

{
  PDNS_A_DATA = ^DNS_A_DATA;
  DNS_A_DATA = record
    IpAddress: IP4_ADDRESS;
  end;
}

PIP4_ARRAY = ^IP4_ARRAY;
IP4_ARRAY=record
	 AddrCount:dword;
	 AddrArray:array [0..10] of IP4_ADDRESS;
end;

PDNS_LOC_DATA = ^DNS_LOC_DATA;
DNS_LOC_DATA=record
	wVersion:WORD;
	wSize:WORD;
	wHorPrec:WORD;
	wVerPrec:WORD;
	dwLatitude:DWORD;
	dwLongitude:DWORD;
	dwAltitude:DWORD;
end;

    DNS_SRV_DATA = record
    pNameTarget: PChar;
    wPriority: Word;
    wWeighty: Word;
    wPorty: Word;
    Pady: Word;                         // keep ptrs DWORD aligned
  end;

  DNS_TSIG_DATA = record
    pNameAlgorithm: PChar;
    pAlgorithmPacket: ^Byte;
    pSignature: ^Byte;
    pOtherData: ^Byte;
    i64CreateTime: longlong;
    wFudgeTime: Word;
    wOriginalXid: Word;
    wError: Word;
    wSigLength: Word;
    wOtherLength: Word;
    cAlgNameLength: UCHAR;
    bPacketPointers: Boolean;
  end;

  DNS_NXT_DATA = record
    pNameNext: PChar;
    wNumTypes: Word;
    wTypes: array[0..1] of Word;
  end;

  DNS_WINSR_DATA = record
    dwMappingFlag: DWORD;
    dwLookupTimeout: DWORD;
    dwCacheTimeout: DWORD;
    pNameResultDomain: PWideChar;
  end;

  DNS_WINSR_DATAA = record
    dwMappingFlag: DWORD;
    dwLookupTimeout: DWORD;
    dwCacheTimeout: DWORD;
    pNameResultDomain: PChar;
  end;



  DNS_TXT_DATA = record
    dwStringCount: DWORD;
    pStringArray: array[0..10] of PChar;
  end;

  DNS_NULL_DATA = record
    dwByteCount: DWORD;
    Data: array[0..10] of Byte;
  end;

  DNS_KEY_DATA = record
    wFlags: Word;
    chProtocol: Byte;
    chAlgorithm: Byte;
    Key: array[0..0] of Byte;
  end;

  DNS_SIG_DATA = record
    pNameSigner: PChar;
    wTypeCovered: Word;
    chAlgorithm: Byte;
    chLabelCount: Byte;
    dwOriginalTtl: DWORD;
    dwExpiration: DWORD;
    dwTimeSigned: DWORD;
    wKeyTag: Word;
    Pad: Word;                          // keep Byte field aligned
    Signature: array[0..0] of Byte;
  end;

  DNS_ATMA_DATA = record
    AddressType: Byte;
    Address: array[0..(DNS_ATMA_MAX_ADDR_LENGTH - 1)] of Byte;
  end;

  DNS_WKS_DATA = record
    IpAddress: IP4_ADDRESS;
    chProtocol: UCHAR;
    BitMask: array[0..0] of Byte;       // BitMask[1];
  end;

  DNS_MX_DATA = record
    pNameExchange: PChar;
    wPreference: Word;
    Pad: Word;
  end;

  DNS_MINFO_DATA = record
    pNameMailbox: PChar;
    pNameErrorsMailbox: PChar;
  end;

  DNS_WINS_DATA = record
    dwMappingFlag: DWORD;
    dwLookupTimeout: DWORD;
    dwCacheTimeout: DWORD;
    cWinsServerCount: DWORD;
    WinsServers: array[0..0] of IP4_ADDRESS;
  end;

  DNS_TKEY_DATA = record
    pNameAlgorithm: PChar;
    pAlgorithmPacket: ^Byte;
    pKey: ^Byte;
    pOtherData: ^Byte;
    dwCreateTime: DWORD;
    dwExpireTime: DWORD;
    wMode: Word;
    wError: Word;
    wKeyLength: Word;
    wOtherLength: Word;
    cAlgNameLength: UCHAR;
    bPacketPointers: Boolean;
  end;

  DNS_SOA_DATA = record
    pNamePrimaryServer: PChar;
    pNameAdministrator: PChar;
    dwSerialNo: DWORD;
    dwRefresh: DWORD;
    dwRetry: DWORD;
    dwExpire: DWORD;
    dwDefaultTtl: DWORD;
  end;


DNS_RECORD_FLAGS = record
    Section: DWORD;                     //DWORD   Section     : 2;
    Delete: DWORD;                      //DWORD   Delete      : 1;
    CharSet: DWORD;                     //DWORD   CharSet     : 2;
    Unused: DWORD;                      //DWORD  Unused      : 3;
    Reserved: DWORD;                    //DWORD  Reserved    : 24;
  end;

pdns_record = ^dns_record;
dns_record=packed record  //28 bytes + 36 bytes data=64
  pnext:pdword;            //4
  pname:lptstr ;          //4 LPTSTR
  wType:word;             //2
  wDataLength:word;       //2
  dw_flags:dword;         //4
  dwTtl:dword;            //4
  dwReserved:dword;       //4
  prt:dword;              //4
  data:array[0..8] of dword;
end;

  {
  PPDNS_RECORD = ^PDNS_RECORD;
  pdns_record = ^dns_record;
  Dns_Record = record
    pNext: PDNS_RECORD;
    pName: LPTSTR;
    wType: WORD;
    wDataLength: WORD; // Not referenced for DNS record types defined above.
    Flags: record
    case Integer of
      0: (DW: DWORD);             // flags as DWORD
      1: (S: DNS_RECORD_FLAGS);   // flags as structure
    end;
    dwTtl: DWORD;
    dwReserved: DWORD;

    //  Record Data

    Data: record
    case Integer of
       0: (A: DNS_A_DATA);
       1: (SOA, Soa_: DNS_SOA_DATA);
       2: (PTR, Ptr_,
           NS, Ns_,
           CNAME, Cname_,
           MB, Mb_,
           MD, Md_,
           MF, Mf_,
           MG, Mg_,
           MR, Mr_: DNS_PTR_DATA);
       3: (MINFO, Minfo_,
           RP, Rp_: DNS_MINFO_DATA);
       4: (MX, Mx_,
           AFSDB, Afsdb_,
           RT, Rt_: DNS_MX_DATA);
       5: (HINFO, Hinfo_,
           ISDN, Isdn_,
           TXT, Txt_,
           X25: DNS_TXT_DATA);
       6: (Null: DNS_NULL_DATA);
       7: (WKS, Wks_: DNS_WKS_DATA);
       8: (AAAA: DNS_AAAA_DATA);
       9: (KEY, Key_: DNS_KEY_DATA);
      10: (SIG, Sig_: DNS_SIG_DATA);
      11: (ATMA, Atma_: DNS_ATMA_DATA);
      12: (NXT, Nxt_: DNS_NXT_DATA);
      13: (SRV, Srv_: DNS_SRV_DATA);
      14: (TKEY, Tkey_: DNS_TKEY_DATA);
      15: (TSIG, Tsig_: DNS_TSIG_DATA);
      16: (WINS, Wins_: DNS_WINS_DATA);
      17: (WINSR, WinsR_, NBSTAT, Nbstat_: DNS_WINSR_DATA);
    end;
   end;
   }


pDnsCacheEntry=^DnsCacheEntry;
DnsCacheEntry=packed record
    pNext:pdword;  // Pointer to next entry
    pszName:LPWSTR;         //PWSTR DNS Record Name
    wType:word;          //unsigned short  DNS Record Type
    wDataLength:word;    //unsigned short  Not referenced
    dwFlags:ulong;        //unsigned long   DNS Record Flags
end;

//validation d'un nom DNS
  DNS_NAME_FORMAT = (DnsNameDomain,
    DnsNameDomainLabel,
    DnsNameHostnameFull,
    DnsNameHostnameLabel,
    DnsNameWildcard,
    DnsNameSrvRecord);

  //définie le type de libération pour avec DnsFreeRecordList
  DNS_FREE_TYPE = (
    DnsFreeFlat,
    DnsFreeRecordList,
    DnsFreeParsedMessageFields
    );



  //problème non résolu lorsqu'on utilise les flags de type S
  {
  TFlags = record
    case Integer of
      1: (DW: DWORD);                   // flags as DWORD
      2: (S: ^DNS_RECORD_FLAGS);        // flags as structure   ???
  end;
  }

  {
  TDataA = record
    case Integer of
      1: (A: DNS_A_DATA);               //    A;
      2: (SOA: DNS_SOA_DATA);          //   SOA, Soa;
      3: (PTR: DNS_PTR_DATA);          //PTR, Ptr, NS, Ns, CNAME, Cname, MB, Mb, MD, Md, MF, Mf, MG, Mg, MR, Mr;
      4: (MINFO: DNS_MINFO_DATA);      //MINFO, Minfo,    RP, Rp;
      5: (MX: DNS_MX_DATA);            //MX, Mx,         AFSDB, Afsdb,             RT, Rt;
      6: (HINFO: DNS_TXT_DATA);        //HINFO, Hinfo,        ISDN, Isdn,        TXT, Txt,          X25;
      7: (Null: DNS_NULL_DATA);         //Null;
      8: (WKS: DNS_WKS_DATA);           //WKS, Wks;
      9: (AAAA: DNS_AAAA_DATA);         //AAAA;
      10: (KEY: DNS_KEY_DATA);          //KEY, Key;
      11: (SIG: DNS_SIG_DATA);         //SIG, Sig;
      12: (ATMA: DNS_ATMA_DATA);        //ATMA, Atma;
      13: (NXT: DNS_NXT_DATA);         //NXT, Nxt;
      14: (SRV: DNS_SRV_DATA);         //SRV, Srv;
      15: (TKEY: DNS_TKEY_DATA);       //TKEY, Tkey;
      16: (TSIG: DNS_TSIG_DATA);       //TSIG, Tsig;
      17: (DWINS: DNS_WINS_DATA);       //WINS, Wins;
      18: (WINSR: DNS_WINSR_DATA);      //WINSR, WinsR, NBSTAT, Nbstat;
  end;
  }

type PVOID=Pointer;  

const
/// Various DNS query types

DNS_QUERY_STANDARD                  = $00000000;
DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE = $00000001;
DNS_QUERY_USE_TCP_ONLY              = $00000002;
DNS_QUERY_NO_RECURSION              = $00000004;
DNS_QUERY_BYPASS_CACHE              = $00000008;
DNS_QUERY_CACHE_ONLY                = $00000010;
DNS_QUERY_NO_LOCAL_NAME             =$00000020;
DNS_QUERY_NO_HOSTS_FILE             =$00000040;
DNS_QUERY_NO_NETBT                  =$00000080;
DNS_QUERY_WIRE_ONLY                 =$00000100;
DNS_QUERY_SOCKET_KEEPALIVE          = $00000100;
DNS_QUERY_RETURN_MESSAGE            =$00000200;
DNS_QUERY_TREAT_AS_FQDN             = $00001000;
DNS_QUERY_ALLOW_EMPTY_AUTH_RESP     = $00010000;
DNS_QUERY_DONT_RESET_TTL_VALUES     = $00100000;
DNS_QUERY_RESERVED                  = $ff000000;
DNS_QUERY_NO_WIRE_QUERY             = $00000010;

  function CreateDnsRecOrd(Hostname: string; IP: string; var newDnsreord: DNS_RECORD): LongInt;
  procedure FreeDnsRecOrd(var newDnsreord: DNS_RECORD);

var
DnsQuery :Function
(lpstrName:lpstr;
 wType:WORD;
   fOptions:DWORD;
  aipServers:pDWORD;
  var ppQueryResultsSet:pdword;
   pReserved:pdword): DWORD; stdcall;

DnsFlushResolverCache :Function: boolean; stdcall;

DnsGetCacheDataTable:function (var pEntry:pdword) : boolean; stdcall;

//ajouter, modifier et supprimer un enregistrement
 DnsModifyRecordsInSet_A:function(
  pAddRecords: PDNS_RECORD;
  pDeleteRecords: PDNS_RECORD;
  Options: DWORD;
  hContext: Hwnd;
  pServerList: PIP4_ARRAY;
  pReserved: Pointer
  ): DNS_STATUS; stdcall;

  //DnsRecordListFree: procedure(pRecordList: PDNS_RECORD; FreeType: DNS_FREE_TYPE); stdcall;
  DnsRecordListFree: procedure(pRecordList: pointer; FreeType: DNS_FREE_TYPE); stdcall;
  DnsFree: procedure(pData: PVOID; FreeType: DNS_FREE_TYPE); stdcall;

implementation

const
  apilib = 'dnsapi.dll';

 var
 Api: THandle = 0;

function InitAPI: Boolean;
begin
  Result := False;
  if api = 0 then Api := LoadLibrary(apilib);
  if Api > HINSTANCE_ERROR then
  begin
    @DnsQuery := GetProcAddress(Api, 'DnsQuery_A');
    @DnsFlushResolverCache := GetProcAddress(Api, 'DnsFlushResolverCache');
    @DnsGetCacheDataTable := GetProcAddress(Api, 'DnsGetCacheDataTable');
    @DnsModifyRecordsInSet_A := GetProcAddress(Api, 'DnsModifyRecordsInSet_A');
    @DnsRecordListFree := GetProcAddress(Api, 'DnsRecordListFree');
    @DnsFree := GetProcAddress(Api, 'DnsFree');
  end;
end;

procedure FreeAPI;
begin
  if Api <> 0 then FreeLibrary(Api);
  Api := 0;
end;

procedure FreeDnsRecOrd(var newDnsreord: DNS_RECORD);
begin
  FreeMem(newDnsreord.pName);
end;
//---

function CreateDnsRecOrd(Hostname: string; IP: string; var newDnsreord: DNS_RECORD): LongInt;
begin
  try
    //GetMem(newDnsreord.pName, Length(Hostname) + 1);
    fillchar(newDnsreord,sizeof(newDnsreord ),0);
    newDnsreord.pName:=allocmem(Length(Hostname) + 1);  //allocmem=getmem+Initialize
    newDnsreord.pnext := nil;
    StrPCopy(newDnsreord.pName, Hostname);
    newDnsreord.wType := DNS_TYPE_A;
    newDnsreord.wDataLength := SizeOf(DNS_A_DATA);
    //newDnsreord.flags  := 32; //???
    newDnsreord.dwTtl := 0;             //durée de vie dans le cache
    newDnsreord.prt := inet_Addr(PansiChar(ansistring(ip))); //string2IP(IP);
    //newDnsreord.Data.A :=inet_Addr(PansiChar(ansistring(ip))); //string2IP(IP);

    //verification si IP valide
    if newDnsreord.prt   <> 0 then CreateDnsRecord := 0  else CreateDnsRecord := 1;
  except
    CreateDnsRecord := 1;
  end;
end;


initialization
  InitAPI;
finalization
  FreeAPI;

end.
