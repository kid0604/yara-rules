rule Linux_Trojan_Gafgyt_09c3070e
{
	meta:
		author = "Elastic Security"
		id = "09c3070e-4b71-45a0-aa62-0cc6e496644a"
		fingerprint = "84fad96b60b297736c149e14de12671ff778bff427ab7684df2c541a6f6d7e7d"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 09c3070e"
		filetype = "executable"

	strings:
		$a = { 48 C1 E8 06 48 89 C6 48 8B 94 C5 50 FF FF FF 8B 8D 2C FF FF FF 83 }

	condition:
		all of them
}
