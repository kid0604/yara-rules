rule Windows_Trojan_Trickbot_b17b33a1
{
	meta:
		author = "Elastic Security"
		id = "b17b33a1-1021-4980-8ffd-2e7aa4ca2ae4"
		fingerprint = "753d15c1ff0cc4cf75250761360bb35280ff0a1a4d34320df354e0329dd35211"
		creation_date = "2021-03-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Trickbot"
		filetype = "executable"

	strings:
		$a = { 08 53 55 56 57 64 A1 30 00 00 00 89 44 24 10 8B 44 24 10 8B }

	condition:
		all of them
}
