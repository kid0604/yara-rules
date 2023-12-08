import "pe"

rule CrunchPEv20xx
{
	meta:
		author = "malware-lu"
		description = "Detects the CrunchPEv20xx malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 E8 [4] 5D 83 ED 06 8B C5 55 60 89 AD [4] 2B 85 [4] 89 85 [4] 55 BB [4] 03 DD 53 64 67 FF 36 [2] 64 67 89 26 }

	condition:
		$a0 at pe.entry_point
}
