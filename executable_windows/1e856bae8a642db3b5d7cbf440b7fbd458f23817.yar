rule Windows_Trojan_IcedID_237e9fb6
{
	meta:
		author = "Elastic Security"
		id = "237e9fb6-b5fa-4747-af1f-533c76a5a639"
		fingerprint = "e2ea6d1477ce4132f123b6c00101a063f7bba7acf38be97ee8dca22cc90ed511"
		creation_date = "2021-02-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.IcedID"
		reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
		reference_sample = "b21f9afc6443548427bf83b5f93e7a54ac3af306d9d71b8348a6f146b2819457"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan IcedID variant 237e9fb6"
		filetype = "executable"

	strings:
		$a = { 60 8B 55 D4 3B D0 7E 45 83 F8 08 0F 4C 45 EC 3B D0 8D 3C 00 0F }

	condition:
		all of them
}
