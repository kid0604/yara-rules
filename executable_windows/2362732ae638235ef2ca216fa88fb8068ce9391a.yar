rule Windows_Generic_Threat_9a8dc290
{
	meta:
		author = "Elastic Security"
		id = "9a8dc290-d9ec-4d52-a4e8-db4ac6ceb164"
		fingerprint = "e9f42a0fdd778b8619633cce87c9d6a3d26243702cdd8a56e524bf48cf759094"
		creation_date = "2024-01-21"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "d951562a841f3706005d7696052d45397e3b4296d4cd96bf187920175fbb1676"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 6F 01 00 06 FE 0E 0B 00 FE 0C 0B 00 FE 0C 09 00 6F 78 01 00 06 FE 0C 0B 00 FE 0C 08 00 28 F2 00 00 06 6F 74 01 00 06 FE 0C 0B 00 FE 0C 07 00 28 F2 00 00 06 6F 76 01 00 06 FE 0C 0B 00 FE 09 00 }

	condition:
		all of them
}
