rule Windows_Generic_Threat_34622a35
{
	meta:
		author = "Elastic Security"
		id = "34622a35-9ddf-4091-8b0c-c9430ecea57c"
		fingerprint = "427762237cd1040bad58e9d9f7ad36c09134d899c5105e977f94933827c5d5e0"
		creation_date = "2024-01-01"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "c021c6adca0ddf38563a13066a652e4d97726175983854674b8dae2f6e59c83f"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 81 EC 88 00 00 00 C7 45 FC 00 00 00 00 C7 45 F8 00 00 00 00 68 4C 00 00 00 E8 A3 42 00 00 83 C4 04 89 45 F4 8B D8 8B F8 33 C0 B9 13 00 00 00 F3 AB 83 C3 38 53 68 10 00 00 00 E8 82 42 }

	condition:
		all of them
}
