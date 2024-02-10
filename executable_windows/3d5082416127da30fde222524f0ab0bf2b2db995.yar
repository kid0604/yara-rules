rule Windows_Generic_Threat_7d555b55
{
	meta:
		author = "Elastic Security"
		id = "7d555b55-20fb-42d4-b337-c267a34fd459"
		fingerprint = "eedf850c3576425fb37291f954dfa39db758cdad0a38f85581d2bcaedcb54769"
		creation_date = "2024-01-22"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "7efa5c8fd55a20fbc3a270cf2329d4a38f10ca372f3428bee4c42279fbe6f9c3"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 EC 40 53 56 57 6A 0F 59 BE 84 77 40 00 8D 7D C0 8B 5D 0C F3 A5 66 A5 8B CB 33 C0 A4 8B 7D 08 8B D1 C1 E9 02 F3 AB 8B CA 83 E1 03 F3 AA 33 C0 8D 7D 0E 50 66 AB FF 15 BC 60 40 00 50 }

	condition:
		all of them
}
