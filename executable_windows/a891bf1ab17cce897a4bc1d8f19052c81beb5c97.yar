import "pe"

rule SoftProtectSoftProtectbyru
{
	meta:
		author = "malware-lu"
		description = "Detects SoftProtect malware by its entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 01 E3 60 E8 03 [3] D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 60 E8 03 [3] 83 EB 0E EB 01 0C 58 EB 01 35 40 EB 01 36 FF E0 0B 61 EB 01 83 9C EB 01 D5 EB 08 35 9D EB 01 89 EB 03 0B EB F7 E8 [4] 58 E8 [4] 59 83 01 01 80 39 5C }

	condition:
		$a0 at pe.entry_point
}
