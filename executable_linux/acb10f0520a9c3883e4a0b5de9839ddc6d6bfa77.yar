rule Linux_Cryptominer_Generic_18af74b2
{
	meta:
		author = "Elastic Security"
		id = "18af74b2-99fe-42fc-aacd-7887116530a8"
		fingerprint = "07a6b44ff1ba6143c76e7ccb3885bd04e968508e93c5f8bff9bc5efc42a16a96"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "52707aa413c488693da32bf2705d4ac702af34faee3f605b207db55cdcc66318"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { 00 70 6F 77 00 6C 6F 67 31 70 00 6C 6F 67 32 66 00 63 65 69 6C 00 }

	condition:
		all of them
}
