rule Linux_Trojan_Mirai_d5f2abe2
{
	meta:
		author = "Elastic Security"
		id = "d5f2abe2-511f-474d-9292-39060bbf6feb"
		fingerprint = "475a1c92c0a938196a5a4bca708b338a62119a2adf36cabf7bc99893fee49f2a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "c490586fbf90d360cf3b2f9e2dc943809441df3dfd64dadad27fc9f5ee96ec74"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with fingerprint d5f2abe2"
		filetype = "executable"

	strings:
		$a = { 41 56 41 89 FE 40 0F B6 FF 41 55 49 89 F5 BE 08 00 00 00 41 54 41 }

	condition:
		all of them
}
