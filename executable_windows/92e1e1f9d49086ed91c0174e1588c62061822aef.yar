import "pe"

rule DxPack10_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of DxPack10_alt_1 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 [4] 5D 8B FD 81 ED [4] 2B B9 [4] 81 EF [4] 83 BD [4] ?? 0F 84 }

	condition:
		$a0 at pe.entry_point
}
