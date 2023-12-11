rule Windows_Trojan_Trickbot_93c9a2a4
{
	meta:
		author = "Elastic Security"
		id = "93c9a2a4-a07a-4ed4-a899-b160d235bf50"
		fingerprint = "0ff82bf9e70304868ff033f0d96e2a140af6e40c09045d12499447ffb94ab838"
		creation_date = "2021-03-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Trickbot variant 93c9a2a4"
		filetype = "executable"

	strings:
		$a = { 6A 01 8B CF FF 50 5C 8B 4F 58 49 89 4F 64 8B 4D F4 8B 45 E4 }

	condition:
		all of them
}
