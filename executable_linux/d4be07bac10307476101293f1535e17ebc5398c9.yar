rule Linux_Trojan_Mobidash_82b4e3f3
{
	meta:
		author = "Elastic Security"
		id = "82b4e3f3-a9ba-477c-8eef-6010767be52f"
		fingerprint = "a01f5ba8b3e8e82ff46cb748fd90a103009318a25f8532fb014722c96f0392db"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mobidash"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mobidash with fingerprint 82b4e3f3"
		filetype = "executable"

	strings:
		$a = { 89 C6 74 2E 89 44 24 0C 8B 44 24 24 C7 44 24 08 01 00 00 00 89 7C }

	condition:
		all of them
}
