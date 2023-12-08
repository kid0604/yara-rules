rule Linux_Trojan_Mirai_2e3f67a9
{
	meta:
		author = "Elastic Security"
		id = "2e3f67a9-6fd5-4457-a626-3a9015bdb401"
		fingerprint = "6a06815f3d2e5f1a7a67f4264953dbb2e9d14e5f3486b178da845eab5b922d4f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Trojan.Mirai variant 2e3f67a9"
		filetype = "executable"

	strings:
		$a = { 53 83 EC 04 0F B6 74 24 14 8B 5C 24 18 8B 7C 24 20 0F B6 44 }

	condition:
		all of them
}
