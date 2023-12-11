import "pe"

rule Protectorv1111DDeMPEEnginev09DDeMCIv092
{
	meta:
		author = "malware-lu"
		description = "Detects Protectorv1111DDeMPEEnginev09DDeMCIv092 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 53 51 56 E8 00 00 00 00 5B 81 EB 08 10 00 00 8D B3 34 10 00 00 B9 F3 03 00 00 BA 63 17 2A EE 31 16 83 C6 04 }

	condition:
		$a0 at pe.entry_point
}
