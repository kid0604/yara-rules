rule Windows_Generic_Threat_f3bef434
{
	meta:
		author = "Elastic Security"
		id = "f3bef434-0688-4672-a02f-40615cc429b1"
		fingerprint = "a05dfdf2f8f15335acb2772074ad42f306a4b33ab6a19bdac99a0215820a6f7b"
		creation_date = "2024-01-12"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "98d538c8f074d831b7a91e549e78f6549db5d2c53a10dbe82209d15d1c2e9b56"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 6F 70 00 06 EB 72 06 26 0A 00 01 45 6F 04 00 00 8F 7B 02 06 26 0A 00 01 44 6F 70 00 06 D5 72 00 00 00 B8 38 1D 2C EB 2C 1A 00 00 00 B8 38 14 04 00 00 8F 7B 00 00 00 BD 38 32 2C 00 00 00 BE 38 }

	condition:
		all of them
}
