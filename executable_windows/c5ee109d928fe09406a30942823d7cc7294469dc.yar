rule Windows_Generic_Threat_61bbb571
{
	meta:
		author = "Elastic Security"
		id = "61bbb571-8544-4874-9811-bd74a5e9f712"
		fingerprint = "be0b1be30cab0789a5df29153187cf812e53cd35dbe31f9527eca2396d7503b5"
		creation_date = "2024-01-29"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "41e2a6cecb1735e8f09b1ba5dccff3c08afe395b6214396e545347927d1815a8"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 EC 14 8B 45 08 53 56 57 8B F9 BE 49 92 24 09 6A 1C 59 89 7D F8 2B 07 99 F7 F9 89 45 FC 8B 47 04 2B 07 99 F7 F9 89 45 F0 3B C6 0F 84 E5 00 00 00 8D 58 01 8B 47 08 2B 07 99 F7 F9 8B }

	condition:
		all of them
}
