rule Linux_Trojan_Gafgyt_a6a2adb9
{
	meta:
		author = "Elastic Security"
		id = "a6a2adb9-9d54-42d4-abed-5b30d8062e97"
		fingerprint = "cdd0bb9ce40a000bb86b0c76616fe71fb7dbb87a044ddd778b7a07fdf804b877"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { CC 01 C2 89 55 B4 8B 45 B4 C9 C3 55 48 89 E5 48 81 EC 90 00 }

	condition:
		all of them
}
