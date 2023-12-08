import "pe"

rule SCObfuscatorSuperCRacker
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the SCObfuscatorSuperCRacker malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 33 C9 8B 1D 00 [3] 03 1D 08 [3] 8A 04 19 84 C0 74 09 3C ?? 74 05 34 ?? 88 04 19 41 3B 0D 04 [3] 75 E7 A1 08 [3] 01 05 0C [3] 61 FF 25 0C }

	condition:
		$a0
}
