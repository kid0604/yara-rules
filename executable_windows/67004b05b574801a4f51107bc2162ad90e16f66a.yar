rule Windows_Generic_Threat_c3c8f21a
{
	meta:
		author = "Elastic Security"
		id = "c3c8f21a-4722-4b6f-85e1-023d45487aeb"
		fingerprint = "5bae56d41d4582aed0a6fd54eab53ce6d47f0d70711cc17e77f8e85019d2ac7e"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "9a102873dd37d08f53dcf6b5dad2555598a954d18fb3090bbf842655c5fded35"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 89 E5 83 EC 14 53 56 57 8D 7D F7 BE 1E CA 40 00 B9 02 00 00 00 F3 A5 A4 68 62 CA 40 00 68 64 CA 40 00 E8 A8 25 00 00 83 C4 08 89 C3 8D 45 EC 50 E8 CA 24 00 00 59 8D 45 EC 50 E8 80 26 00 00 }

	condition:
		all of them
}
