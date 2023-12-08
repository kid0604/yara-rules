import "pe"

rule ROKRAT_Nov17_1
{
	meta:
		description = "Detects ROKRAT malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-11-28"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\T+M\\Result\\DocPrint.pdb" ascii
		$s2 = "d:\\HighSchool\\version 13\\2ndBD" ascii
		$s3 = "e:\\Happy\\Work\\Source\\version" ascii
		$x1 = "\\appdata\\local\\svchost.exe" ascii
		$x2 = "c:\\temp\\esoftscrap.jpg" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <15000KB and 1 of them )
}
