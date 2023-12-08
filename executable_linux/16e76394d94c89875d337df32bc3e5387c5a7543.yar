rule Linux_Trojan_Gafgyt_779e142f
{
	meta:
		author = "Elastic Security"
		id = "779e142f-b867-46e6-b1fb-9105976f42fd"
		fingerprint = "83377b6fa77fda4544c409487d2d2c1ddcef8f7d4120f49a18888c7536f3969f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 779e142f"
		filetype = "executable"

	strings:
		$a = { EC 8B 45 E8 83 E0 02 85 C0 74 07 C7 45 D8 30 00 00 00 8B 45 E8 83 }

	condition:
		all of them
}
