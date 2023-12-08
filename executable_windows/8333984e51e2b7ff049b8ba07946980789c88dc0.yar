import "pe"

rule Joinersignfrompinch250320072010
{
	meta:
		author = "malware-lu"
		description = "Detects Joinersignfrompinch250320072010 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 81 EC 04 01 00 00 8B F4 68 04 01 00 00 56 6A 00 E8 7C 01 00 00 33 C0 6A 00 68 80 00 00 00 6A 03 6A 00 6A 00 68 00 00 00 80 56 E8 50 01 00 00 8B D8 6A 00 6A 00 6A 00 6A 02 6A 00 53 E8 44 01 }

	condition:
		$a0 at pe.entry_point
}
