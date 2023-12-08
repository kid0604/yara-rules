rule Linux_Trojan_Malxmr_7054a0d0
{
	meta:
		author = "Elastic Security"
		id = "7054a0d0-11d4-4671-a88d-ea933e73fe11"
		fingerprint = "9661cc2b7a1d7b882ca39307adc927f5fb73d59f3771a8b456c2cf2ff3d801e9"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Malxmr"
		reference_sample = "3a6b3552ffac13aa70e24fef72b69f683ac221105415efb294fb9a2fc81c260a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Malxmr"
		filetype = "executable"

	strings:
		$a = { 6E 64 47 56 7A 64 48 52 6C 63 33 52 30 5A 58 4E 30 64 47 56 }

	condition:
		all of them
}
