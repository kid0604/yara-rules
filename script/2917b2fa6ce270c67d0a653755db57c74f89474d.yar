import "pe"

rule MALWARE_Win_WSHRAT_alt_1
{
	meta:
		author = "ditekSHen"
		description = "Detects WASHRAT"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "WSH Rat v" wide
		$x2 = "SOFTWARE\\WSHRat" wide
		$x3 = "WSH Remote" wide nocase
		$x4 = "WSHRAT" wide nocase
		$s1 = "shellobj.regwrite \"HKEY_" ascii nocase
		$s2 = "shellobj.run(\"%comspec% /c" ascii nocase
		$s3 = "objhttpdownload.setrequestheader \"user-agent:\"," ascii nocase
		$s4 = "WScript.CreateObject(\"Shell.Application\").ShellExecute" ascii nocase
		$s5 = "objwmiservice.ExecQuery(\"select" ascii nocase
		$s6 = "httpobj.open(\"post\",\"http" ascii nocase
		$s7 = /(rdp|keylogger|get-pass|uvnc)\|http/ wide

	condition:
		uint16(0)==0x5a4d and (2 of ($x*) or (1 of ($x*) and 1 of ($s*)) or (6 of ($s*)))
}
