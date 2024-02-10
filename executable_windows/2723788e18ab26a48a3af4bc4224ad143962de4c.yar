rule Windows_Generic_Threat_cbe3313a
{
	meta:
		author = "Elastic Security"
		id = "cbe3313a-ab8f-4bf1-8f62-b5494c6e7034"
		fingerprint = "dc92cec72728b1df78d79dc5a34ea56ee0b8c8199652c1039288c46859799376"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "1ca2a28c851070b9bfe1f7dd655f2ea10ececef49276c998a1d2a1b48f84cef3"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 EC 08 68 E6 25 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 2C 53 56 57 89 65 F8 C7 45 FC D0 25 40 00 A1 94 B1 41 00 33 F6 3B C6 89 75 EC 89 75 E8 89 75 E4 0F 8E E7 00 00 }

	condition:
		all of them
}
