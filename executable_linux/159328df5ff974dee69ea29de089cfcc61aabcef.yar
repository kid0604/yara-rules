rule Linux_Trojan_Dofloo_1d057993
{
	meta:
		author = "Elastic Security"
		id = "1d057993-0a46-4014-8ab6-aa9e9d93dfa1"
		fingerprint = "c4bb948b85777b1f5df89fafba0674bc245bbda1962c576abaf0752f49c747d0"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Dofloo"
		reference_sample = "88d826bac06c29e1b9024baaf90783e15d87d2a5c8c97426cbd5a70ae0f99461"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Dofloo variant"
		filetype = "executable"

	strings:
		$a = { 10 88 45 DB 83 EC 04 8B 45 F8 83 C0 03 89 45 D4 8B 45 D4 89 }

	condition:
		all of them
}
