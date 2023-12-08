rule Linux_Trojan_Mirai_88a1b067
{
	meta:
		author = "Elastic Security"
		id = "88a1b067-11d5-4128-b763-2d1747c95eef"
		fingerprint = "b32b42975297aed7cef72668ee272a5cfb753dce7813583f0c3ec91e52f8601f"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference = "1a62db02343edda916cbbf463d8e07ec2ad4509fd0f15a5f6946d0ec6c332dd9"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with ID 88a1b067"
		filetype = "executable"

	strings:
		$a = { 00 00 00 55 89 E5 0F B6 55 08 0F B6 45 0C C1 E2 18 C1 E0 10 }

	condition:
		all of them
}
