rule Linux_Trojan_Gafgyt_32eb0c81
{
	meta:
		author = "Elastic Security"
		id = "32eb0c81-25af-4670-ab77-07ea7ce1874a"
		fingerprint = "7c50ed29e2dd75a6a85afc43f8452794cb787ecd2061f4bf415d7038c14c523f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "275cbd5d3b3d8c521649b95122d90d1ca9b7ae1958b721bdc158aaa2d31d49df"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 32eb0c81"
		filetype = "executable"

	strings:
		$a = { D4 48 FF 45 F0 48 8B 45 F0 0F B6 00 84 C0 75 DB EB 12 48 8B }

	condition:
		all of them
}
