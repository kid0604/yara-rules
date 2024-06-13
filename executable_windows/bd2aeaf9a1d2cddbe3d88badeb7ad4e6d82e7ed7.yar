rule Windows_Generic_Threat_38a88967
{
	meta:
		author = "Elastic Security"
		id = "38a88967-db0e-4d68-9295-9108cbc98fb9"
		fingerprint = "1fef2c4c2899bbf9f45732d23654f6437658de2c4dc78dc3d1ff5440b5c2cbcf"
		creation_date = "2024-03-25"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "6e425eb1a27c4337f05d12992e33fe0047e30259380002797639d51ef9509739"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 60 E8 00 00 00 00 5B ?? ?? ?? ?? ?? ?? 8B 75 08 8B 7D 0C AD 50 53 89 C1 29 DB 29 C0 AC C1 E3 04 01 C3 AA 89 D8 ?? ?? ?? ?? ?? 85 C0 74 07 89 C2 C1 EA 18 31 D3 F7 D0 21 C3 E2 DF 87 DA }

	condition:
		all of them
}
