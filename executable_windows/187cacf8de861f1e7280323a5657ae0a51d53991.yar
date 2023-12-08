rule Windows_Trojan_Generic_bbe6c282
{
	meta:
		author = "Elastic Security"
		id = "bbe6c282-e92d-4021-bdaf-189337e4abf0"
		fingerprint = "e004d77440a86c23f23086e1ada6d1453178b9c2292782c1c88a7b14151c10fe"
		creation_date = "2022-03-02"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Generic"
		reference_sample = "a44c46d4b9cf1254aaabd1e689f84c4d2c3dd213597f827acabface03a1ae6d1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Generic with fingerprint bbe6c282"
		filetype = "executable"

	strings:
		$a1 = { 00 D1 1C A5 03 08 08 00 8A 5C 01 08 08 00 8A 58 01 2E 54 FF }

	condition:
		all of them
}
