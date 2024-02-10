rule Windows_Generic_Threat_6b621667
{
	meta:
		author = "Elastic Security"
		id = "6b621667-8ed2-4a6e-9fad-fc7a01012859"
		fingerprint = "77d3637fea6d1ddca7b6943671f2d776fa939b063d60d8b659a0fc63acfdc869"
		creation_date = "2024-01-31"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "b50b39e460ecd7633a42f0856359088de20512c932fc35af6531ff48c9fa638a"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 51 64 A1 30 00 00 00 56 33 F6 89 75 FC 8B 40 10 39 70 08 7C 0F 8D 45 FC 50 E8 8F 0D 00 00 83 7D FC 01 74 03 33 F6 46 8B C6 5E C9 C3 8B FF 55 8B EC 51 51 53 56 6A 38 6A 40 E8 32 EB FF }

	condition:
		all of them
}
