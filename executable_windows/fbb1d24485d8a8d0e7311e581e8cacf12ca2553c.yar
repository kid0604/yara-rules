rule Windows_Trojan_Trickbot_997b25a0
{
	meta:
		author = "Elastic Security"
		id = "997b25a0-aeac-4f74-aa87-232c4f8329b6"
		fingerprint = "0bba1c5284ed0548f51fdfd6fb96e24f92f7f4132caefbf0704efb0b1a64b7c4"
		creation_date = "2021-03-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Trickbot variant 997b25a0"
		filetype = "executable"

	strings:
		$a = { 85 D2 74 F0 C6 45 E1 20 8D 4D E1 C6 45 E2 4A C6 45 E3 4A C6 45 }

	condition:
		all of them
}
