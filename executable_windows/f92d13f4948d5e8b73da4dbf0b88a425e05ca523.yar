import "pe"

rule RCryptorv1Vaska
{
	meta:
		author = "malware-lu"
		description = "Detects RCryptorv1Vaska malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 }
		$a1 = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 [4] B8 [4] 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
