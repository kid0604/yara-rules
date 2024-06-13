rule Windows_Generic_Threat_e8abb835
{
	meta:
		author = "Elastic Security"
		id = "e8abb835-f0c1-4e27-a0ca-3a3cae3362df"
		fingerprint = "ca8c2f4b16ebe1bb48c91a536d8aca98bed5592675eff9311e77d7e06dfe3c5b"
		creation_date = "2024-03-26"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "e42262671325bec300afa722cefb584e477c3f2782c8d4c6402d6863df348cac"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 48 81 EC 28 05 00 00 66 44 0F 7F 84 24 10 05 00 00 66 0F 7F BC 24 00 05 00 00 0F 29 B4 24 F0 04 00 00 44 89 44 24 74 48 89 94 24 C8 00 00 00 48 89 CB 48 C7 44 24 78 00 00 00 00 0F 57 F6 0F 29 }

	condition:
		all of them
}
