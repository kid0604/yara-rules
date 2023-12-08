import "pe"

rule VxUddy2617
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 2E [5] 2E [5] 2E [3] 8C C8 8E D8 8C [3] 2B [3] 03 [3] A3 [2] A1 [2] A3 [2] A1 [2] A3 [2] 8C C8 2B [3] 03 [3] A3 [2] B8 AB 9C CD 2F 3D 76 98 }

	condition:
		$a0 at pe.entry_point
}
