import "pe"

rule UPXSCRAMBLER306OnToL
{
	meta:
		author = "malware-lu"
		description = "Detects UPX packed and scrambled files with specific entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 59 83 C1 07 51 C3 C3 BE [4] 83 EC 04 89 34 24 B9 80 00 00 00 81 36 [4] 50 B8 04 00 00 00 50 03 34 24 58 58 83 E9 03 E2 E9 EB D6 }

	condition:
		$a0 at pe.entry_point
}
