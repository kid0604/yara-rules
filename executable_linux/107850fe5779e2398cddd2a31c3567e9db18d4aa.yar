rule Linux_Worm_Generic_3ff8f75b
{
	meta:
		author = "Elastic Security"
		id = "3ff8f75b-619e-4090-8ea4-aedc8bdf61a4"
		fingerprint = "011f0cd72ebb428775305c84eac69c5ff4800de6e1d8b4d2110d5445b1aae10f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Worm.Generic"
		reference_sample = "991175a96b719982f3a846df4a66161a02225c21b12a879e233e19124e90bd35"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Worm.Generic based on specific string"
		filetype = "executable"

	strings:
		$a = { 3A DF FE 00 66 0F 73 FB 04 66 0F 6F D3 66 0F EF D9 66 0F 6F EE 66 0F 70 }

	condition:
		all of them
}
