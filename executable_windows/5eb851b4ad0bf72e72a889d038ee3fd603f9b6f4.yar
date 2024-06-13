rule Windows_Generic_Threat_4db75701
{
	meta:
		author = "Elastic Security"
		id = "4db75701-e7d6-4231-ba00-e127da90bfce"
		fingerprint = "d8637b329a212bf37367ba3cc3acf65c9b511d1f06d689d792c519324459530d"
		creation_date = "2024-03-05"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "fa7847d21d5a350cf96d7ecbcf13dce63e6a0937971cfb479700c5b31850bba9"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 48 81 EC D0 02 00 00 80 79 20 08 41 8B F1 45 8B F0 4C 8B FA 48 8B F9 0F 84 3A 01 00 00 48 89 58 10 48 89 68 18 43 8D 04 40 48 63 C8 ?? ?? ?? ?? ?? 48 8D 8C 24 20 02 00 00 }

	condition:
		all of them
}
