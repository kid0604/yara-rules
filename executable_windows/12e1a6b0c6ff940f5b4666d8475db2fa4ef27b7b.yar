import "pe"

rule Ningishzida10CyberDoom
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Ningishzida10CyberDoom malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 96 E8 00 00 00 00 5D 81 ED 03 25 40 00 B9 04 1B 00 00 8D BD 4B 25 40 00 8B F7 AC [48] AA E2 CC }

	condition:
		$a0 at pe.entry_point
}
