rule Windows_Trojan_Trickbot_34f00046
{
	meta:
		author = "Elastic Security"
		id = "34f00046-8938-4103-91ec-4a745a627d4a"
		fingerprint = "5c6f11e2a040ae32336f4b4c4717e0f10c73359899302b77e1803f3a609309c0"
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
		$a = { 30 FF FF FF 03 08 8B 95 30 FF FF FF 2B D1 89 95 30 FF FF FF }

	condition:
		all of them
}
