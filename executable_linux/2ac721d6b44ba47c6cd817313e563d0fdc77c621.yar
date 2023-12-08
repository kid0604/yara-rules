rule Linux_Trojan_Mirai_1cb033f3
{
	meta:
		author = "Elastic Security"
		id = "1cb033f3-68c1-4fe5-9cd1-b5d066c1d86e"
		fingerprint = "49201ab37ff0b5cdfa9b0b34b6faa170bd25f04df51c24b0b558b7534fecc358"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 1cb033f3"
		filetype = "executable"

	strings:
		$a = { C3 EB 06 8A 46 FF 88 47 FF FF CA 48 FF C7 48 FF C6 83 FA FF }

	condition:
		all of them
}
