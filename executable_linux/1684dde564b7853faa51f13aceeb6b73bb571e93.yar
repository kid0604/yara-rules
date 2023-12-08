rule Linux_Trojan_Gafgyt_e6d75e6f
{
	meta:
		author = "Elastic Security"
		id = "e6d75e6f-aa04-4767-8730-6909958044a7"
		fingerprint = "e99805e8917d6526031270b6da5c2f3cc1c8235fed1d47134835a107d0df497c"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "48b15093f33c18778724c48c34199a420be4beb0d794e36034097806e1521eb8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { 00 00 00 CD 80 C3 8B 54 24 04 8B 4C 24 08 87 D3 B8 5B 00 00 00 }

	condition:
		all of them
}
