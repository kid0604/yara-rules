rule Windows_Trojan_Trickbot_a0fc8f35
{
	meta:
		author = "Elastic Security"
		id = "a0fc8f35-cbeb-43a8-b00d-7a0f981e84e4"
		fingerprint = "033ff4f47fece45dfa7e3ba185df84a767691e56f0081f4ed96f9e2455a563cb"
		creation_date = "2021-03-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Trickbot (a0fc8f35)"
		filetype = "executable"

	strings:
		$a = { 18 33 DB 53 6A 01 53 53 8D 4C 24 34 51 8B F0 89 5C 24 38 FF D7 }

	condition:
		all of them
}
