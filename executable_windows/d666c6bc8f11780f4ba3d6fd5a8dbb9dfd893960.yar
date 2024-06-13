rule Windows_Generic_Threat_b191061e
{
	meta:
		author = "Elastic Security"
		id = "b191061e-7b83-4161-a1d4-05ab70ffe2be"
		fingerprint = "5733de0357a6b5f6a3fe885786084c23707266b48e67b19dcddc48ed97e94207"
		creation_date = "2024-03-04"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "bd4ef6fae7f29def8e5894bf05057653248f009422de85c1e425d04a0b2df258"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 EC 2C 64 A1 30 00 00 00 33 D2 53 56 57 8B 40 0C 8B F2 89 4D E8 89 55 F4 89 75 F8 8B 58 0C 8B 7B 18 89 7D F0 85 FF 0F 84 34 01 00 00 C7 45 E0 60 00 00 00 8B 43 30 89 55 FC 89 55 EC }

	condition:
		all of them
}
