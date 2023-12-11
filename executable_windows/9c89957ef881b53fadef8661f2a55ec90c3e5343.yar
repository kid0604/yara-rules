import "pe"

rule VxHafen809
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 1C ?? 81 EE [2] 50 1E 06 8C C8 8E D8 06 33 C0 8E C0 26 [3] 07 3D }

	condition:
		$a0 at pe.entry_point
}
