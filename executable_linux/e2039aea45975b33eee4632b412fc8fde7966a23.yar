rule Linux_Trojan_Ladvix_db41f9d2
{
	meta:
		author = "Elastic Security"
		id = "db41f9d2-aa5c-4d26-b8ba-cece44eddca8"
		fingerprint = "d0aaa680e81f44cc555bf7799d33fce66f172563788afb2ad0fb16d3e460e8c6"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ladvix"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Ladvix"
		filetype = "executable"

	strings:
		$a = { C0 49 89 C4 74 45 45 85 ED 7E 26 48 89 C3 41 8D 45 FF 4D 8D 7C }

	condition:
		all of them
}
