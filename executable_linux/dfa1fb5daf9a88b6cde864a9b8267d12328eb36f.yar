rule Linux_Trojan_Sshdoor_32d9fb1b
{
	meta:
		author = "Elastic Security"
		id = "32d9fb1b-79d7-4bd1-bbe5-345550591367"
		fingerprint = "fa28250df6960ee54de7b0bacb437b543615a241267e34b5a422f231f5088f10"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Sshdoor"
		reference_sample = "ee1f6dbea40d198e437e8c2ae81193472c89e41d1998bee071867dab1ce16b90"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Sshdoor with ID 32d9fb1b"
		filetype = "executable"

	strings:
		$a = { 8B 04 25 28 00 00 00 48 89 44 24 08 31 C0 66 0F EF C0 48 85 F6 }

	condition:
		all of them
}
