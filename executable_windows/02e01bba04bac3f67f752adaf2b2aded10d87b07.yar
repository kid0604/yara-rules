import "pe"

rule SoftDefenderv11xRandyLi
{
	meta:
		author = "malware-lu"
		description = "Yara rule for SoftDefenderv11xRandyLi malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 74 07 75 05 [6] 74 1F 75 1D ?? 68 [3] 00 59 9C 50 74 0A 75 08 ?? 59 C2 04 00 [3] E8 F4 FF FF FF [3] 78 0F 79 0D }

	condition:
		$a0 at pe.entry_point
}
