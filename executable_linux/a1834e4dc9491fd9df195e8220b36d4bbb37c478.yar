rule Linux_Trojan_Gafgyt_cf84c9f2
{
	meta:
		author = "Elastic Security"
		id = "cf84c9f2-7435-4faf-8c5f-d14945ffad7a"
		fingerprint = "bb766b356c3e8706740e3bb9b4a7171d8eb5137e09fc7ab6952412fa55e2dcfc"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with fingerprint cf84c9f2"
		filetype = "executable"

	strings:
		$a = { 55 48 89 E5 48 83 EC 30 48 89 7D E8 89 75 E4 89 55 E0 C7 45 F8 01 00 }

	condition:
		all of them
}
