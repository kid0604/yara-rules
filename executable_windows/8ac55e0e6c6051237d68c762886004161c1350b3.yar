rule Windows_Generic_Threat_803feff4
{
	meta:
		author = "Elastic Security"
		id = "803feff4-e4c2-4d8c-b736-47bb10fd5ce8"
		fingerprint = "3bbb00aa18086ac804f6ddf99a50821744a420f46b6361841b8bcd2872e597f1"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "8f150dfb13e4a2ff36231f873e4c0677b5db4aa235d8f0aeb41e02f7e31c1e05"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat with fingerprint 803feff4"
		filetype = "executable"

	strings:
		$a1 = { 6F 01 00 06 6F 25 00 00 0A 02 7B 03 00 00 04 73 8D 01 00 06 6F 25 00 00 0A 02 7B 03 00 00 04 73 92 01 00 06 6F 25 00 00 0A 02 7B 03 00 00 04 73 9A 01 00 06 6F 25 00 00 0A 02 7B 03 00 00 04 73 }

	condition:
		all of them
}
