rule Windows_Generic_Threat_642df623
{
	meta:
		author = "Elastic Security"
		id = "642df623-00ae-48a9-8d61-aaa688606807"
		fingerprint = "fb2c74f7e3e7f4e25173c375fe863e643183da4f5d718d61fdd0271fcc581deb"
		creation_date = "2024-02-20"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "e5ba85d1a6a54df38b5fa655703c3457783f4a4f71e178f83d8aac878d4847da"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 50 B8 04 00 00 00 81 C4 04 F0 FF FF 50 48 75 F6 8B 45 FC 81 C4 3C FE FF FF 53 56 57 64 8B 05 30 00 00 00 8B 40 0C 8B 40 0C 8B 00 8B 00 8B 40 18 89 45 FC 33 C9 8B 45 FC 89 45 DC 8B 45 }

	condition:
		all of them
}
