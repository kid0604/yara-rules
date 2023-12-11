import "pe"

rule UPXECLiPSElayer
{
	meta:
		author = "malware-lu"
		description = "Detects UPXECLiPSElayer malware based on entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [4] B9 [4] 33 D2 EB 01 0F 56 EB 01 0F E8 03 00 00 00 EB 01 0F EB 01 0F 5E EB 01 }

	condition:
		$a0 at pe.entry_point
}
