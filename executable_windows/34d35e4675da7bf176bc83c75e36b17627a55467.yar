import "pe"

rule RCryptorv16bv16cVaska
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting RCryptorv16bv16cVaska malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 }
		$a1 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 [4] B8 [4] 3D [4] 74 06 80 30 ?? 40 EB F3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
