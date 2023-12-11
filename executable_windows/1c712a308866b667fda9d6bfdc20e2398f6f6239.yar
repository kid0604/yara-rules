import "pe"

rule HKTL_Amplia_Security_Tool
{
	meta:
		description = "Detects Amplia Security Tool like Windows Credential Editor"
		score = 60
		nodeepdive = 1
		author = "Florian Roth"
		date = "2013-01-01"
		modified = "2023-02-14"
		os = "windows"
		filetype = "executable"

	strings:
		$a = "Amplia Security"
		$c = "getlsasrvaddr.exe"
		$d = "Cannot get PID of LSASS.EXE"
		$e = "extract the TGT session key"
		$f = "PPWDUMP_DATA"

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and (2 of them ) or 3 of them
}
