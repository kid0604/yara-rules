import "pe"

rule UpackV037Dwing
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Upack v0.37 Dwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 0B 01 [14] 18 10 00 00 10 00 00 00 [8] 00 10 00 00 00 02 00 00 [12] 00 00 00 00 [32] 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 [4] 14 00 00 00 [40] 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 }
		$a1 = { 60 E8 09 00 00 00 [9] 33 C9 5E 87 0E }
		$a2 = { BE [4] AD 50 FF [2] EB }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}
