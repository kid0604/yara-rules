rule Windows_Generic_Threat_42b3e0d7
{
	meta:
		author = "Elastic Security"
		id = "42b3e0d7-ec42-4940-b5f3-e9782997dccf"
		fingerprint = "7d3974400d05bc7bbcd63c99e8257d0676b38335de74a4bcfde9e86553f50f08"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "99ad416b155970fda383a63fe61de2e4d0254e9c9e09564e17938e8e2b49b5b7"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 C4 F8 53 33 DB 6A 00 8D 45 F8 50 8B 45 0C 50 8B 45 10 50 6A 00 6A 00 33 C9 33 D2 8B 45 08 E8 B1 F7 FF FF 85 C0 75 05 BB 01 00 00 00 8B C3 5B 59 59 5D C2 0C 00 8D 40 00 53 BB E0 E1 }

	condition:
		all of them
}
