rule Linux_Trojan_Mirai_c8385b81
{
	meta:
		author = "Elastic Security"
		id = "c8385b81-0f5b-41c3-94bb-265ede946a84"
		fingerprint = "dfdbd4dbfe16bcf779adb16352d5e57e3950e449e96c10bf33a91efee7c085e5"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "3d27736caccdd3199a14ce29d91b1812d1d597a4fa8472698e6df6ef716f5ce9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { 8D 74 26 00 89 C2 83 ED 04 C1 E2 0B 31 C2 89 F0 C1 E8 13 89 D1 }

	condition:
		all of them
}
