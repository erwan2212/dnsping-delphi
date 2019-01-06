unit utils;

interface

uses winsock,windows;

function IPdwordToString(LeWord: LongWord): String;
function string2IP(ip:string):dword;
function IsStrNumericExt(const S: String): Boolean;
function split(input:string;schar:char;s:integer):string;
function SystemErrorMessage: string;overload;
function SystemErrorMessage(err:dword): string;overload;

implementation

function SystemErrorMessage: string;overload;
var
  P: PChar;
begin
  if FormatMessage(Format_Message_Allocate_Buffer + Format_Message_From_System,
                   nil,
                   GetLastError,
                   0,
                   @P,
                   0,
                   nil) <> 0 then
  begin
    Result := P;
    LocalFree(Integer(P))
  end
  else
    Result := '';
end;

function SystemErrorMessage(err:dword): string;overload;
var
  P: PChar;
begin
  if FormatMessage(Format_Message_Allocate_Buffer + Format_Message_From_System,
                   nil,
                   err,
                   0,
                   @P,
                   0,
                   nil) <> 0 then
  begin
    Result := P;
    LocalFree(Integer(P))
  end
  else
    Result := '';
end;

function split(input:string;schar:char;s:integer):string;
    var
       i,n:integer;
       schop: string;
    begin
       n := 1;
       for i := 1 to length(input)+1 do
       begin
         if (input[i] = schar) or (i=length(input)+1) then
         begin
           inc(n);
           if n = s then split := schop
                    else schop := '';
         end
         else schop := schop + input[i];
       end;
end;

function string2IP(ip:string):dword;
begin
result:=inet_Addr(PansiChar(ansistring(ip)));
end;

function IPdwordToString(LeWord: LongWord): String;
var
 Adr : TInAddr ;
begin
//strpas(inet_ntoa(tinaddr(pchar(leword))))
 Adr.S_addr := LeWord ;
 result := inet_ntoa(Adr) ;
end;

function IsStrNumericExt(const S: String): Boolean;
var
   Numeric : Set of Char;
   iCnt    : Integer;
begin
  Result:=True;
  Numeric:=['0'..'9','.']; // Here you can add other chars
  For iCnt:=1 to Length(S) do
    begin
    If Not (S[iCnt] in Numeric) then
      begin
      Result:=False;
      Exit;
      end;
    end;
end;


end.
