import "pe"

rule VxNoon1163
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 5B 50 56 B4 CB CD 21 3C 07 [2] 81 [3] 2E [2] 4D 5A [2] BF 00 01 89 DE FC }

	condition:
		$a0 at pe.entry_point
}
