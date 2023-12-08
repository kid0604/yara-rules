import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_ClearWinLogs
{
	meta:
		author = "ditekSHen"
		description = "Detects executables containing commands for clearing Windows Event Logs"
		os = "windows"
		filetype = "executable"

	strings:
		$cmd1 = "wevtutil.exe clear-log" ascii wide nocase
		$cmd2 = "wevtutil.exe cl " ascii wide nocase
		$cmd3 = ".ClearEventLog()" ascii wide nocase
		$cmd4 = "Foreach-Object {wevtutil cl \"$_\"}" ascii wide nocase
		$cmd5 = "('wevtutil.exe el') DO (call :do_clear" ascii wide nocase
		$cmd6 = "| ForEach { Clear-EventLog $_.Log }" ascii wide nocase
		$cmd7 = "('wevtutil.exe el') DO wevtutil.exe cl \"%s\"" ascii wide nocase
		$cmd8 = "Clear-EventLog -LogName application, system, security" ascii wide nocase
		$t1 = "wevtutil" ascii wide nocase
		$l1 = "cl Application" ascii wide nocase
		$l2 = "cl System" ascii wide nocase
		$l3 = "cl Setup" ascii wide nocase
		$l4 = "cl Security" ascii wide nocase
		$l5 = "sl Security /e:false" ascii wide nocase
		$ne1 = "wevtutil.exe cl Aplicaci" fullword wide
		$ne2 = "wevtutil.exe cl Application /bu:C:\\admin\\backup\\al0306.evtx" fullword wide
		$ne3 = "wevtutil.exe cl Application /bu:C:\\admin\\backups\\al0306.evtx" fullword wide

	condition:
		uint16(0)==0x5a4d and not any of ($ne*) and ((1 of ($cmd*)) or (1 of ($t*) and 3 of ($l*)))
}
