rule Windows_Generic_Threat_d8f834a9
{
	meta:
		author = "Elastic Security"
		id = "d8f834a9-41b7-4fc9-8100-87b9b07c0bc7"
		fingerprint = "fcf7fc680c762ffd9293a84c9ac2ba34b18dc928417ebdabd6dfa998f96ed1f6"
		creation_date = "2024-01-29"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "c118c2064a5839ebd57a67a7be731fffe89669a8f17c1fe678432d4ff85e7929"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 C4 F4 53 56 57 8B F9 8B F2 8B D8 33 D2 8A 55 08 0F AF 53 30 D1 FA 79 03 83 D2 00 03 53 30 8B 43 34 E8 62 48 04 00 89 45 FC 68 20 00 CC 00 8B 45 20 50 57 56 8B 45 FC 8B 10 FF 52 20 }

	condition:
		all of them
}
