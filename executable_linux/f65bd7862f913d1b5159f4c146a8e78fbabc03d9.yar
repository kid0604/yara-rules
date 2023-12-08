rule Linux_Cryptominer_Generic_e0cca9dc
{
	meta:
		author = "Elastic Security"
		id = "e0cca9dc-0f3e-42d8-bb43-0625f4f9bfe1"
		fingerprint = "e7bc17ba356774ed10e65c95a8db3b09d3b9be72703e6daa9b601ea820481db7"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "59a1d8aa677739f2edbb8bd34f566b31f19d729b0a115fef2eac8ab1d1acc383"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 54 24 40 48 8D 94 24 C0 00 00 00 F3 41 0F 6F 01 48 89 7C 24 50 48 89 74 }

	condition:
		all of them
}
