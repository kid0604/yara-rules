rule Linux_Trojan_Gafgyt_ad12b9b6
{
	meta:
		author = "Elastic Security"
		id = "ad12b9b6-2e66-4647-8bf3-0300f2124a97"
		fingerprint = "46d86406f7fb25f0e240abc13e86291c56eb7468d0128fdff181f28d4f978058"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Gafgyt"
		reference = "f0411131acfddb40ac8069164ce2808e9c8928709898d3fb5dc88036003fe9c8"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { 4C 52 46 00 4B 45 46 31 4A 43 53 00 4B 45 46 31 51 45 42 00 }

	condition:
		all of them
}
