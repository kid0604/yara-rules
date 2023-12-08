rule Windows_Trojan_Trickbot_1e56fad7
{
	meta:
		author = "Elastic Security"
		id = "1e56fad7-383f-4ee0-9f8f-a0b3dcceb691"
		fingerprint = "a0916134f47df384bbdacff994970f60d3613baa03c0a581b7d1dd476af3121b"
		creation_date = "2021-03-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Trickbot variant with fingerprint 1e56fad7"
		filetype = "executable"

	strings:
		$a = { 5B C9 C2 18 00 43 C1 02 10 7C C2 02 10 54 C1 02 10 67 C1 02 10 }

	condition:
		all of them
}
