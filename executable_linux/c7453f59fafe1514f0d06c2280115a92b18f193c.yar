rule Linux_Trojan_Xorddos_884cab60
{
	meta:
		author = "Elastic Security"
		id = "884cab60-214f-4879-aa51-c00de1a5ffc4"
		fingerprint = "47895e9c8acf66fc853c7947dc53730967d5a4670ef59c96569c577e1a260a72"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Xorddos"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { E4 8B 51 64 F6 C2 10 75 12 89 CB 89 D1 83 C9 40 89 D0 F0 0F B1 }

	condition:
		all of them
}
