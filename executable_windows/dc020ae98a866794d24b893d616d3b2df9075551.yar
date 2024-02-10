rule Windows_Generic_Threat_4a605e93
{
	meta:
		author = "Elastic Security"
		id = "4a605e93-971d-4257-b382-065159840a4c"
		fingerprint = "58185f9fdf5bbc57cd708d8c963a37824e377a045549f2eb78d5fa501082b687"
		creation_date = "2024-01-29"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "1a84e25505a54e8e308714b53123396df74df1bde223bb306c0dc6220c1f0bbb"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 20 48 8B 19 45 33 C0 48 85 DB 74 65 4C 89 01 48 83 FA FF 75 17 41 8B C0 44 38 03 74 2D 48 8B CB 48 FF C1 FF C0 44 38 01 75 F6 EB 1E 48 83 FA FE 75 1B 41 8B C0 66 44 39 03 74 0F 48 8B }

	condition:
		all of them
}
