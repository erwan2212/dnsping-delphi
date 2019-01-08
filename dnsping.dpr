program dnsping;

{$APPTYPE CONSOLE}

uses
  sysutils,
  windows,
  dnsapi,
  regexpr,
  utils in 'utils.pas';

var
ret:longint;  

function isvalidip(ip:string):boolean;
begin
try
result:=ExecRegExpr  ('^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$',ip);
except
result:=false;
end;
end;

//0 if exists
function DnsEntryExists(server,Hostname: string): LongInt;
var
  ppQueryResultsSet:pdword;//PDNS_RECORD;
  chAZT: array[0..255] of Char;
  aipServers: IP4_array;
  p:pointer;
begin
  try
    StrPCopy(chAZT, Hostname);

aipServers.AddrCount := 1;
aipServers.AddrArray[0] := string2IP(server );
if server<>'' then p:=@aipservers else p:=nil;

    //nom d'hote
    result := DnsQuery(chAZT,
      DNS_TYPE_A,
      DNS_QUERY_STANDARD {+ DNS_QUERY_BYPASS_CACHE},
      p,
      ppQueryResultsSet,
      nil);

    //free ppQueryResultsSet
    //DnsRecordListFree(ppQueryResultsSet, DnsFreeRecordList);
  except
    raise;
  end;
end;

//https://docs.microsoft.com/en-us/windows/desktop/debug/system-error-codes--9000-11999-
function DelDnsEntry(server,Hostname,ip: string): LongInt;
var
  QueryToSet: DNS_RECORD;
  rep: LongInt;
  p:pointer;
  aipServers:ip4_array;
begin
aipServers.AddrCount := 1;
aipServers.AddrArray[0] := string2IP(server );
if server<>'' then p:=@aipServers else p:=nil;

  try
    if (ip <> '') then
    begin
      //crée le record
      CreateDnsRecOrd(Hostname, ip, QueryToSet);
      //envois la requete d'ajout
      DelDnsEntry := DnsModifyRecordsInSet_A(
        nil,
        @QueryToSet,
        DNS_UPDATE_SECURITY_USE_DEFAULT ,
        0,
        p,
        nil);
      FreeDnsRecOrd(QueryToSet);
    end
    else
      DelDnsEntry := 9501;              // Invalid IP address
  except
    on e:exception do raise exception.create(e.message);
  end;
end;


//https://docs.microsoft.com/en-us/windows/desktop/debug/system-error-codes--9000-11999-
function AddDnsEntry(server,Hostname,IP: string): LongInt;
var
  QueryToSet: DNS_RECORD;
  rep: LongInt;
  aipServers:ip4_array;
  p:pointer;
begin
result:=0;
aipServers.AddrCount := 1;
aipServers.AddrArray[0] := string2IP(server );
if server<>'' then p:=@aipservers else p:=nil;

  try
    //test s'il existe deja
    rep := DnsEntryExists(server,Hostname);
    if (rep <> 0) then
    begin
      //crée le record et verification si IP valid
      if (CreateDnsRecOrd(Hostname, IP, QueryToSet) = 0) then
      begin
        //envois la requete d'ajout
        AddDnsEntry := DnsModifyRecordsInSet_A(
          @QueryToSet,
          nil,
          DNS_UPDATE_SECURITY_USE_DEFAULT,
          0,
          p,
          nil);
        FreeDnsRecOrd(QueryToSet);
      end //if (CreateDnsRecOrd(Hostname, IP, QueryToSet) = 0)
      else
        AddDnsEntry := 9552;            // Invalid IP address
    end //if (rep <> 0) then
    else
      AddDnsEntry := 9555;              //Record for given name and type is not unique
  except
    on e:exception do raise exception.create(e.Message );
  end;
end;

procedure GetDnsCache;
var
myptr,entries:pdword ;
ret:boolean;
entry:DnsCacheEntry ;
myptr2,dnsrecords:pdword;
dnsrecord:dns_record;
begin
if not Assigned(DnsGetCacheDataTable) then
  begin
  raise exception.create ('DnsGetCacheDataTable not assigned!');
  exit;
  end;

ret:=DnsGetCacheDataTable(entries);

if ret=true then
  begin
  if entries=nil then begin writeln('cache empty');exit;end;
  myptr:=entries;
  try
  repeat
  fillchar(entry,sizeof(entry),0);
  copymemory(@entry,myptr,sizeof(entry));
  //writeln(pchar(string(entry.pszName)));
  if (entry.pszName <>nil) and (entry.wType <>0) then
    begin
    dnsrecords:=nil;
    DnsQuery( pchar(string(entry.pszName)), entry.wType , DNS_QUERY_STANDARD {DNS_QUERY_CACHE_ONLY}, nil,  dnsrecords, nil );
    myptr2:=dnsrecords;
    repeat
    if myptr2 <>nil then
      begin
      copymemory(@dnsrecord,myptr2,sizeof(dnsrecord));
      writeln ('****************');
      writeln ('Name:'+pchar(string(entry.pszName)));
      writeln ('Type:'+inttostr(entry.wType ));
      writeln ('TTL:'+inttostr(dnsrecord.dwTtl ));
      case entry.wType of
       DNS_TYPE_A:writeln('StringPointer:'+ipdwordtostring(dword(dnsrecord.prt )));
       DNS_TYPE_CNAME : writeln('StringPointer:'+pchar(dnsrecord.prt  ));
       DNS_TYPE_PTR :writeln('StringPointer:'+pchar(dnsrecord.prt  ));
       DNS_TYPE_TEXT :writeln('StringPointer:'+pchar(dnsrecord.data [0] ));
       else writeln('StringPointer:'+pchar(dnsrecord.prt))
      end; //case
      //writeln ('****************');
      end;//if pdnsrecord <>nil then
      myptr2:=dnsrecord.pnext;
      until (dnsrecord.pnext=nil); // or (myptr2=dnsrecords );
    //free dnsrecord !!!
    end;//if (entry.pszName <>nil) and (entry.wType <>0) then
  myptr:=entry.pnext;
  until (entry.pnext=nil);// or (myptr=entries);
DnsFree (entries,DnsFreeRecordList);
except
on e:exception do raise exception.create(e.Message );
end;
end //if ret=true then
else writeln('DnsGetCacheDataTable false');

end;


procedure ping(server,dnsentry:string);
var
dns_rec:dns_record;
strip:array[0..3] of string;
dnstype:word;
ret,querytype:dword;
myptr,ppQueryResultsSet:pdword;
buf:array[0..63] of byte;
aipServers: IP4_array;
before,after:dword;
begin

if not Assigned(dnsquery) then
  begin
  writeln('DNSQUERY not assigned!');
  exit;
  end;

dnstype:= 1; //TYPE_A

if (isvalidip(dnsentry)=true) and (dnstype<>DNS_TYPE_PTR) then    DNSType := DNS_TYPE_PTR;

If (DNSType = DNS_TYPE_PTR)
And
(pos(uppercase(dnsentry),'.IN-ADDR.ARPA') = 0) Then
    begin
    if IsStrNumericExt(dnsentry[1])=false then
      begin
      writeln('You have selected DNS_TYPE_PTR :You must enter an IP.');
      exit;
      end;
      strIP[3]:= Split(DNSEntry, '.',5);
      strIP[2]:= Split(DNSEntry, '.',4);
      strIP[1]:= Split(DNSEntry, '.',3);
      strIP[0]:= Split(DNSEntry, '.',2);
      DNSEntry:= strIP[3] + '.' + strIP[2] + '.' + strIP[1] + '.' + strIP[0] + '.IN-ADDR.ARPA';
    End;

querytype:=0;

querytype:=DNS_QUERY_TREAT_AS_FQDN;
querytype:=querytype or DNS_QUERY_WIRE_ONLY;
querytype:=querytype or DNS_QUERY_BYPASS_CACHE;
querytype:=querytype or DNS_QUERY_NO_HOSTS_FILE;

ppQueryResultsSet:=nil;

  aipServers.AddrCount := 1;
  aipServers.AddrArray[0] := string2IP(server );
  try
  //send the query
  before:=gettickcount;
  ret:=DnsQuery( pchar(dnsentry), dnstype, querytype, @aipservers,  ppQueryResultsSet, nil );
  after:=gettickcount;
  except
  on e:exception do begin writeln(formatdatetime('hh:nn:ss', now)+' '+e.Message );exit;end;
  end;


if ret<>0 then begin writeln(formatdatetime('hh:nn:ss', now)+' '+SystemErrorMessage(ret)+' time:'+inttostr(after-before));exit;end;

myptr:=nil;
myptr:=ppQueryResultsSet;
if myptr=nil then exit;
try
repeat
fillchar(dns_rec,64,0);
copymemory(@dns_rec,myptr,64);

if dns_rec.pname<>nil then write (formatdatetime('hh:nn:ss', now)+' ',dns_rec.pname);
if dns_rec.wtype=DNS_TYPE_A then
   begin
      writeln (' ['+ipdwordtostring(dns_rec.prt)+'] TTL:'+inttostr(dns_rec.dwTtl)+ ' time:'+inttostr(after-before));
   end
   else if dns_rec.wtype=DNS_TYPE_TEXT
   then
      begin
      if dns_rec.prt <>0 then
      try
      writeln(' ['+pchar(dns_rec.data [0])+'] TTL:'+inttostr(dns_rec.dwTtl)+ ' time:'+inttostr(after-before));
      except
      end;
   end
   else if dns_rec.prt <>0
   then
      begin
      try
      writeln(' ['+pchar(dns_rec.Data[0] )+'] TTL:'+inttostr(dns_rec.dwTtl)+ ' time:'+inttostr(after-before));
      except
      end;
   end;

myptr:=dns_rec.pnext;
until (dns_rec.pnext=nil) or (myptr=ppQueryResultsSet);

if( ppQueryResultsSet )<>nil then DnsRecordListFree( ppQueryResultsSet, DnsFreeRecordList );
except
on e:exception do writeln(formatdatetime('hh:nn:ss', now)+' '+e.Message );
end;

end;

begin
  if paramcount=0 then
  begin
  writeln('dnsping 0.6 by erwan2212@gmail.com');
  writeln('usage: dnsping query nameserver query');
  writeln('usage: dnsping query nameserver query delay_seconds');
  writeln('usage: dnsping cache');
  writeln('usage: dnsping flush');
  writeln('usage: dnsping add nameserver hostname ip');
  writeln('usage: dnsping delete nameserver hostname ip');  
  end;
//******************************************************************  
  if lowercase(Paramstr(1))='flush' then
    begin
    try
    if DnsFlushResolverCache=true then writeln('ok') else writeln('failed') ;
    except
    on e:exception do writeln(e.Message);
    end;
    exit;
    end;
  if lowercase(Paramstr(1))='cache' then
    begin
    try GetDnsCache ; except on e:exception do writeln(e.Message);end;
    exit;
    end;
//*********************************************************************  
  if lowercase(Paramstr(1))='add' then
    begin
    ret:= AddDnsEntry(Paramstr(2),Paramstr(3), Paramstr(4));
    if ret=0 then writeln('ok') else writeln('failed:'+inttostr(ret));
    exit;
    end;
  if lowercase(Paramstr(1))='delete' then
    begin
    ret:= DelDnsEntry(Paramstr(2),Paramstr(3), Paramstr(4));
    if ret=0 then writeln('ok') else writeln('failed:'+inttostr(ret));
    exit;
    end;
//********************************************************************
  if lowercase(Paramstr(1))='query' then
  begin
  writeln('timestamp query result ttl duration');
  if paramcount<4
    then ping(paramstr(2),paramstr(3))
    else
    begin
    while 1=1 do
      begin
      ping(paramstr(2),paramstr(3));
      sleep(strtoint(paramstr(4))*1000);
      end;
    end;
  end;
end.
