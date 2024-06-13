rule Windows_Generic_Threat_c34e19e9
{
	meta:
		author = "Elastic Security"
		id = "c34e19e9-c666-4fc5-bbb3-75f64d247899"
		fingerprint = "148ffb1f73a3f337d188c78de638880ea595a812dfa7a0ada6dc66805637aeb3"
		creation_date = "2024-03-04"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "f9048348a59d9f824b45b16b1fdba9bfeda513aa9fbe671442f84b81679232db"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 28 00 00 0A 73 18 00 00 0A 7E 02 00 00 04 17 8D 3A 00 00 01 25 16 1F 2C 9D 6F 28 00 00 0A 8E 69 6F 29 00 00 0A 9A 0A 7E 01 00 00 04 17 8D 3A 00 00 01 25 16 1F 2C 9D 6F 28 00 00 0A 73 18 00 00 }

	condition:
		all of them
}
