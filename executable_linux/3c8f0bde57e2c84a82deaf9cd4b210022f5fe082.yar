rule Linux_Trojan_Mirai_eedfbfc6
{
	meta:
		author = "Elastic Security"
		id = "eedfbfc6-98a4-4817-a0d6-dcb065307f5c"
		fingerprint = "c79058b4a40630cb4142493062318cdfda881259ac95b70d977816f85b82bb36"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "b7342f7437a3a16805a7a8d4a667e0e018584f9a99591413650e05d21d3e6da6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with fingerprint eedfbfc6"
		filetype = "executable"

	strings:
		$a = { 7C 39 57 52 AC 57 A8 CE A8 8C FC 53 A8 A8 0E 33 C2 AA 38 14 FB 29 }

	condition:
		all of them
}
