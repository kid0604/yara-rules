rule Linux_Trojan_Gafgyt_31796a40
{
	meta:
		author = "Elastic Security"
		id = "31796a40-1cbe-4d0c-a785-d16f40765f4a"
		fingerprint = "0a6c56eeed58a1a100c9b981157bb864904ffddb3a0c4cb61ec4cc0d770d68ae"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "227c7f13f7bdadf6a14cc85e8d2106b9d69ab80abe6fc0056af5edef3621d4fb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 31796a40"
		filetype = "executable"

	strings:
		$a = { 14 48 63 D0 48 8D 45 C0 48 8D 70 04 48 8B 45 E8 48 8B 40 18 48 }

	condition:
		all of them
}
