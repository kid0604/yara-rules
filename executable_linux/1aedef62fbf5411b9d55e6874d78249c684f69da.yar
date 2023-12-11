rule Linux_Trojan_Dofloo_be1973ed
{
	meta:
		author = "Elastic Security"
		id = "be1973ed-a0ee-41ca-a752-fb5f990e2096"
		fingerprint = "f032f072fd5da9ec4d8d3953bea0f2a236219b99ecfa67e3fac44f2e73f33e9c"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Dofloo"
		reference_sample = "88d826bac06c29e1b9024baaf90783e15d87d2a5c8c97426cbd5a70ae0f99461"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Dofloo"
		filetype = "executable"

	strings:
		$a = { A8 8B 45 A8 89 45 A4 83 7D A4 00 79 04 83 45 A4 03 8B 45 A4 C1 }

	condition:
		all of them
}
