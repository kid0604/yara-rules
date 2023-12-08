rule Windows_Trojan_Trickbot_06fd4ac4
{
	meta:
		author = "Elastic Security"
		id = "06fd4ac4-1155-4068-ae63-4d83db2bd942"
		fingerprint = "ece49004ed1d27ef92b3b1ec040d06e90687d4ac5a89451e2ae487d92cb24ddd"
		creation_date = "2021-03-28"
		last_modified = "2021-08-23"
		description = "Identifies Trickbot unpacker"
		threat_name = "Windows.Trojan.Trickbot"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a = { 5F 33 C0 68 ?? ?? 00 00 59 50 E2 FD 8B C7 57 8B EC 05 ?? ?? ?? 00 89 45 04 }

	condition:
		all of them
}
