import "pe"

rule ScObfuscatorSuperCRacker
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of ScObfuscatorSuperCRacker malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 33 C9 8B 1D [4] 03 1D [4] 8A 04 19 84 C0 74 09 3C ?? 74 05 34 ?? 88 04 19 41 3B 0D [4] 75 E7 A1 [4] 01 05 [4] 61 FF 25 [4] 00 00 }

	condition:
		$a0 at pe.entry_point
}
