rule Linux_Exploit_Sorso_61eae7dd
{
	meta:
		author = "Elastic Security"
		id = "61eae7dd-3335-4a50-b70b-c7c5657fc540"
		fingerprint = "8ada74a60e30a26f7789bfdf00b3373843f39dc7d71bd6e1b603a7a41b5a63e9"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Sorso"
		reference_sample = "c0f0a7b45fb91bc18264d901c20539dd32bc03fa5b7d839a0ef5012fb0d895cd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Exploit.Sorso"
		filetype = "executable"

	strings:
		$a = { 69 89 E3 50 53 89 E1 B0 0B CD 80 31 C0 B0 01 CD }

	condition:
		all of them
}
