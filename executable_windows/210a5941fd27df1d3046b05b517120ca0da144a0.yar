import "pe"

rule RCryptorv16Vaska
{
	meta:
		author = "malware-lu"
		description = "Detects the RCryptorv16Vaska malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 33 D0 68 [4] FF D2 }
		$a1 = { 33 D0 68 [4] FF D2 B8 [4] 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
