import "pe"

rule tElockv099SpecialBuildheXerforgot
{
	meta:
		author = "malware-lu"
		description = "Detects tElockv099SpecialBuildheXerforgot malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 5E DF FF FF 00 00 00 [4] E5 [2] 00 00 00 00 00 00 00 00 00 05 [2] 00 F5 [2] 00 ED [2] 00 00 00 00 00 00 00 00 00 12 [2] 00 FD [2] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1D [2] 00 00 00 00 00 30 [2] 00 00 }
		$a1 = { E9 5E DF FF FF 00 00 00 [4] E5 [2] 00 00 00 00 00 00 00 00 00 05 [2] 00 F5 [2] 00 ED [2] 00 00 00 00 00 00 00 00 00 12 [2] 00 FD [2] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1D [2] 00 00 00 00 00 30 [2] 00 00 00 00 00 1D [2] 00 00 00 00 00 30 [2] 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
