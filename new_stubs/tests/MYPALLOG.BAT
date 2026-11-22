@ECHO OFF
REM Starts Mypal with Mozilla's own network logging switched on (log: C:\MOZLOG*.*).
REM Runs itself again in a COMMAND.COM with room for the long variables.
IF "%1"=="GO" GOTO GO
COMMAND /E:4096 /C %0 GO
GOTO END
:GO
SET MOZ_LOG=timestamp,nsHostResolver:5,GetAddrInfo:5,nsSocketTransport:5,nsHttp:3,proxy:5
SET MOZ_LOG_FILE=C:\MOZLOG.TXT
SET NSPR_LOG_MODULES=timestamp,nsHostResolver:5,GetAddrInfo:5,nsSocketTransport:5,nsHttp:3,proxy:5
SET NSPR_LOG_FILE=C:\MOZLOG.TXT
ECHO Starting Mypal with network logging...
START C:\WINDOWS\DESKTOP\MYPAL\MYPAL.EXE
:END
