import "pe"

rule UPXcrypterarchphaseNWC
{
	meta:
		author = "malware-lu"
		description = "Detects UPX encrypted files with specific architecture phase"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BF [3] 00 81 FF [3] 00 74 10 81 2F ?? 00 00 00 83 C7 04 BB 05 [2] 00 FF E3 BE [3] 00 FF E6 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
