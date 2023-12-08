import "pe"

rule RCryptorv13bVaska
{
	meta:
		author = "malware-lu"
		description = "Detects RCryptorv13bVaska malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 61 83 EF 4F 60 68 [4] FF D7 }
		$a1 = { 61 83 EF 4F 60 68 [4] FF D7 B8 [4] 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
