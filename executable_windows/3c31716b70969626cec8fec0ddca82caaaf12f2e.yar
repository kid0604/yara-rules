rule Windows_Trojan_Trickbot_515504e2
{
	meta:
		author = "Elastic Security"
		id = "515504e2-6b7f-4398-b89b-3af2b46c78a7"
		fingerprint = "8eb741e1b3bd760e2cf511ad6609ac6f1f510958a05fb093eae26462f16ee1d0"
		creation_date = "2021-03-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Trickbot variant 515504e2"
		filetype = "executable"

	strings:
		$a = { 6A 00 6A 00 8D 4D E0 51 FF D6 85 C0 74 29 83 F8 FF 74 0C 8D }

	condition:
		all of them
}
