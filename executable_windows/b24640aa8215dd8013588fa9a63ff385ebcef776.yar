rule Windows_Generic_Threat_c374cd85
{
	meta:
		author = "Elastic Security"
		id = "c374cd85-714b-47c5-8645-cc7918fa2ff1"
		fingerprint = "4936566b7f3f8250b068aa8e4a9b745c3e9ce2fa35164a94e77b31068d3d6ebf"
		creation_date = "2024-01-31"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "1c677585a8b724332849c411ffe2563b2b753fd6699c210f0720352f52a6ab72"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 EC 0C 53 8B 5E 74 39 9E 44 01 00 00 75 07 33 C0 E9 88 00 00 00 57 8B BE E0 00 00 00 85 FF 74 79 8B 8E E4 00 00 00 85 C9 74 6F 8B 86 44 01 00 00 8B D0 03 C7 8D 4C 01 F8 2B D3 89 4D }

	condition:
		all of them
}
