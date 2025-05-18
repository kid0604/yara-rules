rule Windows_Trojan_Smokeloader_bf391fe0
{
	meta:
		author = "Elastic Security"
		id = "bf391fe0-7e7f-4f29-8a8c-c13aa2c1eef1"
		fingerprint = "513355978aca1f1dd21c199c7fbf72a59639ad08d0c8712d7d076a67da737ab5"
		creation_date = "2024-08-27"
		last_modified = "2024-09-30"
		threat_name = "Windows.Trojan.Smokeloader"
		reference_sample = "fe2489230d024f5e0e7d0da0210f93e70248dc282192c092cbb5e0eddc7bd528"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Smokeloader"
		filetype = "executable"

	strings:
		$a = { 8A 54 3C 18 0F B6 C2 03 F0 23 F1 8A 44 34 18 88 44 3C 18 88 54 34 18 0F B6 4C 3C 18 }
		$b = { 8D 87 77 05 00 00 50 8B 44 24 18 05 36 01 00 00 50 }

	condition:
		any of them
}
