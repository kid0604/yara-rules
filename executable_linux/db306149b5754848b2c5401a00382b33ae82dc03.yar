rule Linux_Cryptominer_Camelot_25b63f54
{
	meta:
		author = "Elastic Security"
		id = "25b63f54-8a32-4866-8f90-b2949f5e7539"
		fingerprint = "c0bc4f5fc0ad846a90e214dfca8252bf096463163940930636c1693c7f3833fa"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Camelot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Camelot"
		filetype = "executable"

	strings:
		$a = { 0F 6F 39 66 41 0F 6F 32 66 4D 0F 7E C3 66 44 0F D4 CB 66 45 0F }

	condition:
		all of them
}
