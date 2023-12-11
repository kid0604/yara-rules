import "pe"

rule VxNcuLi1688
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 0E 1E B8 55 AA CD 21 3D 49 4C 74 ?? 0E 0E 1F 07 E8 }

	condition:
		$a0 at pe.entry_point
}
