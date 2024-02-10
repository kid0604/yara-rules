rule Windows_Generic_Threat_3a321f0a
{
	meta:
		author = "Elastic Security"
		id = "3a321f0a-2775-455f-b8c2-30591ebfe4ac"
		fingerprint = "230c3bbc70ec93888f5cd68598dcc004844db67f17d1048a51f6c6408bc4a956"
		creation_date = "2024-01-29"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "91056e8c53dc1e97c7feafab31f0943f150d89a0b0026bcfb3664d2e93ccfe2b"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 EC 44 8D 45 14 8B 4D 10 85 C9 89 5D F8 89 7D FC 0F 8E 3D 01 00 00 49 8D 55 17 83 E2 FC 89 4D 10 85 C9 8D 42 08 8B 58 F8 8B 78 FC 89 5D D4 89 7D D8 0F 8E 31 01 00 00 83 C2 0B 49 83 }

	condition:
		all of them
}
