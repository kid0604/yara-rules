rule Windows_Generic_Threat_1417511b
{
	meta:
		author = "Elastic Security"
		id = "1417511b-2b31-47a8-8465-b6a174174863"
		fingerprint = "4be19360fccf794ca2e53c4f47cd1becf476becf9eafeab430bdb3c64581613c"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "2fc9bd91753ff3334ef7f9861dc1ae79cf5915d79fa50f7104cbb3262b7037da"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 EC 20 8B 45 08 89 45 F4 8B 4D F4 8B 55 08 03 51 3C 89 55 F0 B8 08 00 00 00 6B C8 00 8B 55 F0 8B 45 08 03 44 0A 78 89 45 F8 8B 4D F8 8B 55 08 03 51 20 89 55 EC 8B 45 F8 8B 4D 08 03 }

	condition:
		all of them
}
