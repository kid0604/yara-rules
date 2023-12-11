rule Linux_Exploit_Lotoor_4f8d83d2
{
	meta:
		author = "Elastic Security"
		id = "4f8d83d2-4f7b-4a55-9d08-f7bc84263302"
		fingerprint = "1a4e2746eb1da2a841c08ea44c6d0476c02dae5b4fbbe17926433bdb8c4e6df5"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Lotoor"
		reference_sample = "d78128eca706557eeab8a454cf875362a097459347ddc32118f71bd6c73d5bbd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Exploit.Lotoor malware"
		filetype = "executable"

	strings:
		$a = { 00 75 6E 61 6D 65 00 73 74 64 6F 75 74 00 66 77 72 69 74 65 00 }

	condition:
		all of them
}
