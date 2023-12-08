rule Linux_Trojan_Mirai_612b407c
{
	meta:
		author = "Elastic Security"
		id = "612b407c-fceb-4a19-8905-2f5b822f62cc"
		fingerprint = "c48c26b1052ef832d4d6a106db186bf20c503bdf38392a1661eb2d3c3ec010cd"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "7833bc89778461a9f46cc47a78c67dda48b498ee40b09a80a21e67cb70c6add1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 612b407c"
		filetype = "executable"

	strings:
		$a = { 11 B2 73 45 2B 7A 57 E2 F9 77 A2 23 EC 7C 0C 29 FE 3F B2 DE 28 6C }

	condition:
		all of them
}
