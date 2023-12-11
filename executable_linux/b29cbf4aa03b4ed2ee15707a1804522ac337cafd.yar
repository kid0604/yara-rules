rule Linux_Trojan_Setag_351eeb76
{
	meta:
		author = "Elastic Security"
		id = "351eeb76-ccca-40d5-8ee3-e8daf6494dda"
		fingerprint = "c6edc7ae898831e9cc3c92fcdce4cd5b4412de061575e6da2f4e07776e0885f5"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Setag"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Setag"
		filetype = "executable"

	strings:
		$a = { 04 8B 45 F8 C1 E0 02 01 C2 8B 45 EC 89 02 8D 45 F8 FF 00 8B }

	condition:
		all of them
}
