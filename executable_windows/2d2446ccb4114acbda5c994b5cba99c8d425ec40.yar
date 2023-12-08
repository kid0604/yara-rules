import "pe"

rule MALWARE_Win_SmokeLoader
{
	meta:
		author = "ditekSHen"
		description = "Detects SmokeLoader variants"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "G2A/CLP/05/RYS" fullword wide
		$x2 = "0N1Y/53R10U5/BU51N355" fullword wide
		$x3 = "CH4PG3PB-6HT2VI9C-O2NL2NO5-QP1BW0EG" fullword wide
		$s1 = "Azure-Update-Task" fullword wide
		$s2 = "C:\\Windows\\System32\\schtasks.exe" fullword wide
		$s3 = "/C /create /F /sc minute /mo 1 /tn \"" fullword wide
		$s4 = "\\Microsoft\\Network" fullword wide
		$s5 = "\\Microsoft\\TelemetryServices" fullword wide
		$s6 = "\" /tr \"" fullword wide
		$e1 = "\\sqlcmd.exe" fullword wide
		$e2 = "\\sihost.exe" fullword wide
		$e3 = "\\fodhelper.exe" fullword wide

	condition:
		uint16(0)==0x5a4d and ((1 of ($x*) and 4 of ($s*)) or (5 of ($s*) and 1 of ($e*)))
}
