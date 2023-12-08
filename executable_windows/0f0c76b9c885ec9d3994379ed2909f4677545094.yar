import "pe"

rule SimplePack1XMethod2bagie
{
	meta:
		author = "malware-lu"
		description = "Detects SimplePack1XMethod2bagie malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 4D 5A 90 EB 01 00 52 E9 ?? 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 [3] 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 }

	condition:
		$a0
}
