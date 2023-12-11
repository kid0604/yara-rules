rule Windows_Trojan_NapListener_e8f16920
{
	meta:
		author = "Elastic Security"
		id = "e8f16920-52ca-46b6-a945-1b919f975aae"
		fingerprint = "36689095792e7eb7fce23e7d390675a3554c8a5ba4356aaf9c2fa8986d3a0439"
		creation_date = "2023-02-28"
		last_modified = "2023-03-20"
		threat_name = "Windows.Trojan.NapListener"
		reference_sample = "6e8c5bb2dfc90bca380c6f42af7458c8b8af40b7be95fab91e7c67b0dee664c4"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan NapListener"
		filetype = "executable"

	strings:
		$start_routine = { 02 28 08 00 00 0A 00 00 28 03 00 00 0A 0A 14 FE 06 04 00 00 06 73 04 00 00 0A 73 05 00 00 0A 0B 16 28 06 00 00 0A 00 07 06 6F 07 00 00 0A 00 00 2A }
		$main_routine = { 6F 22 00 00 0A 13 0E 11 0D 1F 24 14 16 8D 16 00 00 01 14 6F 23 00 00 0A 13 0F 11 0F 14 6F 24 00 00 0A 13 10 11 0E 11 10 18 8D 01 00 00 01 }
		$start_thread = { 00 28 03 00 00 0A 0A 14 FE 06 04 00 00 06 73 04 00 00 0A 73 05 00 00 0A 0B 16 28 06 00 00 0A 00 07 06 6F 07 00 00 0A 00 2A }

	condition:
		2 of them
}
