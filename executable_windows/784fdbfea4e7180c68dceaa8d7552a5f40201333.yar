rule Windows_Generic_Threat_d170474c
{
	meta:
		author = "Elastic Security"
		id = "d170474c-7d9b-4f19-8166-b2c96a8a90b8"
		fingerprint = "acc79131046a279c4a0746703649870fe8c88025ec0d370ee68f34cbdbf3d7b6"
		creation_date = "2024-10-10"
		last_modified = "2024-11-26"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "63da7ea6d4cd240485ad5c546dd60b90cb98d6f4f18df4bc708f5ec689be952f"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 28 02 00 06 6F 36 03 00 06 11 00 28 DC 00 00 06 02 03 11 00 73 7E 00 00 06 13 01 7E 64 00 00 04 13 0F 16 13 03 11 03 11 0F 8E 69 2F 22 11 0F 11 03 9A 13 04 11 04 12 01 6F 83 00 00 06 DE 08 13 }

	condition:
		all of them
}
