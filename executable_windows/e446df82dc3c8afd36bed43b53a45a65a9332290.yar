rule Windows_Trojan_RedLineStealer_f07b3cb4
{
	meta:
		author = "Elastic Security"
		id = "f07b3cb4-a1c5-42c3-a992-d6d9a48bc7a0"
		fingerprint = "8687fa6f540ccebab6000c0c93be4931d874cd04b0692c6934148938bac0026e"
		creation_date = "2023-05-03"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "5e491625475fc25c465fc7f6db98def189c15a133af7d0ac1ecbc8d887c4feb6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan RedLineStealer"
		filetype = "executable"

	strings:
		$a1 = { 3C 65 6E 63 72 79 70 74 65 64 5F 6B 65 79 3E 6B 5F 5F 42 61 63 6B 69 6E 67 46 69 65 6C 64 }
		$a2 = { 45 42 37 45 46 31 39 37 33 43 44 43 32 39 35 42 37 42 30 38 46 45 36 44 38 32 42 39 45 43 44 41 44 31 31 30 36 41 46 32 }

	condition:
		all of them
}
