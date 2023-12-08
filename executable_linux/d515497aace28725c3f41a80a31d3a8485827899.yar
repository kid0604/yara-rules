rule Linux_Trojan_Mirai_d8779a57
{
	meta:
		author = "Elastic Security"
		id = "d8779a57-c6ee-4627-9eb0-ab9305bd2454"
		fingerprint = "6c7a18cc03cacef5186d4c1f6ce05203cf8914c09798e345b41ce0dcee1ca9a6"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "c490586fbf90d360cf3b2f9e2dc943809441df3dfd64dadad27fc9f5ee96ec74"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { B6 FF 41 89 D0 85 FF 74 29 38 56 08 74 28 48 83 C6 10 31 D2 }

	condition:
		all of them
}
