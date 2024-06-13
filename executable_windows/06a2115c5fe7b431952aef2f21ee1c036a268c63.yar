rule Windows_Generic_Threat_59698796
{
	meta:
		author = "Elastic Security"
		id = "59698796-0022-486a-a743-6931745f38a0"
		fingerprint = "9260d02c3e6b163fd376445bd2a9c084ed85a5dbaf0509e15fff4e9c3d147f19"
		creation_date = "2024-03-04"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "35f9698e9b9f611b3dd92466f18f97f4a8b4506ed6f10d4ac84303177f43522d"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 81 EC B8 04 00 00 ?? ?? ?? ?? ?? 33 C5 89 45 FC 56 68 00 04 00 00 0F 57 C0 C7 45 F8 00 00 00 00 8D 85 58 FB FF FF C7 85 54 FB FF FF 24 00 00 00 6A 00 50 8B F1 0F 11 45 D8 0F 11 45 E8 }

	condition:
		all of them
}
