import "pe"

rule FishPEV10Xhellfish
{
	meta:
		author = "malware-lu"
		description = "Detects FishPEV10Xhellfish malware based on entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 [4] C3 90 09 00 00 00 2C 00 00 00 [4] C4 03 00 00 BC A0 00 00 00 40 01 00 [4] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 99 00 00 00 00 8A 00 00 00 10 00 00 [2] 00 00 [4] 00 00 02 00 00 00 A0 00 00 18 01 00 00 [4] 00 00 0C 00 00 00 B0 00 00 38 0A 00 00 [4] 00 00 00 00 00 00 C0 00 00 40 39 00 00 [4] 00 00 08 00 00 00 00 01 00 C8 06 00 00 }

	condition:
		$a0 at pe.entry_point
}
