rule Linux_Trojan_Tsunami_40c25a06
{
	meta:
		author = "Elastic Security"
		id = "40c25a06-5f3c-42c1-9a8c-5c4a1568ff9a"
		fingerprint = "b45d666e2e7d571e95806a1a2c8e01cd5cd0d71160cbb06b268110d459ee252d"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "61af6bb7be25465e7d469953763be5671f33c197d4b005e4a78227da11ae91e9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { 20 74 13 9C B8 20 07 09 20 35 15 11 03 20 85 }

	condition:
		all of them
}
