rule Linux_Trojan_Mirai_76908c99
{
	meta:
		author = "Elastic Security"
		id = "76908c99-e350-4dbb-9559-27cbe05f55f9"
		fingerprint = "1741b0c2121e3f73bf7e4f505c4661c95753cbf7e0b7a1106dc4ea4d4dd73d6c"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "533a90959bfb337fd7532fb844501fd568f5f4a49998d5d479daf5dfbd01abb2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Mirai (76908c99)"
		filetype = "executable"

	strings:
		$a = { 64 24 F8 48 89 04 24 48 8B C6 48 8B 34 24 48 87 CF 48 8B 4C }

	condition:
		all of them
}
