rule Windows_Generic_Threat_0cc1481e
{
	meta:
		author = "Elastic Security"
		id = "0cc1481e-d666-4443-852c-679ef59e4ee4"
		fingerprint = "3dac71f8cbe7cb12066e91ffb6da6524891654fda249fa5934946fd5a2120360"
		creation_date = "2023-12-17"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "6ec7781e472a6827c1406a53ed4699407659bd57c33dd4ab51cabfe8ece6f23f"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 C4 A8 53 56 57 8B FA 8B D8 8B 43 28 3B 78 10 0F 84 B4 00 00 00 8B F0 85 FF 75 15 83 7E 04 01 75 0F 8B 46 10 E8 03 A7 FF FF 33 C0 89 46 10 EB 7C 8B C3 E8 B5 F3 FF FF 8B C3 E8 BE F3 }

	condition:
		all of them
}
