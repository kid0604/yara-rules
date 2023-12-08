import "pe"

rule CrunchPEv30xx
{
	meta:
		author = "malware-lu"
		description = "Detects the CrunchPEv30xx malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 10 [16] 55 E8 [4] 5D 81 ED 18 [3] 8B C5 55 60 9C 2B 85 [4] 89 85 [4] FF 74 }

	condition:
		$a0 at pe.entry_point
}
