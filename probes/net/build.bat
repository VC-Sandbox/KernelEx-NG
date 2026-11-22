@echo off
set FW=C:\WINDOWS\Microsoft.NET\Framework\v4.0.30319
%FW%\csc.exe /nologo /out:C:\KEXTEST\HELLO.EXE C:\KEXTEST\hello.cs > C:\CSC.TXT
%FW%\csc.exe /nologo /target:winexe /out:C:\KEXTEST\FORM.EXE C:\KEXTEST\form.cs >> C:\CSC.TXT
