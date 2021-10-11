library SniffDll;

uses
  WinTypes, WinProcs, Messages;

const
  KeyEvent=WM_USER+1;
  MouseEvent=KeyEvent+1;
  WinTitle='TKeyForm';

var
  HookHandle, MouseHandle: HHOOK;

function KeyHook(code: integer; WParam: word; lParam: Longint): Longint; stdcall;
var
  Wnd: hWnd;
begin
  if (code = HC_ACTION) and (lParam <> lParam or $8000 shl 16)
                      and (lParam <> lParam or $8000 shl 15) then
    begin
      Wnd:=FindWindow(WinTitle, nil);
      SendMessage(Wnd, KeyEvent, wParam, lParam);
    end;
  Result:=CallNextHookEx(HookHandle, code, WParam, lParam);
end;

function MouseHook(code: integer; WParam: word; lParam: Longint): Longint;StdCall;
var
  Wnd: hWnd;
begin
  if (code = HC_ACTION) then
    begin
      Wnd:=FindWindow(WinTitle, nil);
      SendMessage(Wnd, MouseEvent, wParam, lParam);
    end;
  Result:=CallNextHookEx(MouseHandle, code, WParam, lParam);
end;

procedure SetKeyHook; export;
begin
  HookHandle:=SetWindowsHookEx(WH_KEYBOARD, @KeyHook, hInstance, 0);
  MouseHandle:=SetWindowsHookEx(WH_MOUSE, @MouseHook, hInstance, 0);
end;

procedure DelKeyHook; export;
begin
  if HookHandle <> 0 then
    UnhookWindowsHookEx(HookHandle);
  HookHandle:=0;
  if MouseHandle <> 0 then
    UnhookWindowsHookEx(MouseHandle);
  MouseHandle:=0;
  HookHandle:=0;
end;

exports
  SetKeyHook name 'SetKeyHook',
  DelKeyHook name 'DelKeyHook';

begin
end.
