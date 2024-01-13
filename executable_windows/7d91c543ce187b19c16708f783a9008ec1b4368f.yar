rule Windows_Generic_Threat_232b71a9
{
	meta:
		author = "Elastic Security"
		id = "232b71a9-add2-492d-8b9a-ad2881826ecf"
		fingerprint = "908e2a968e544dfb08a6667f78c92df656c7f2c5cf329dbba6cfdb5ea7b51a57"
		creation_date = "2023-12-20"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "1e8b34da2d675af96b34041d4e493e34139fc8779f806dbcf62a6c9c4d9980fe"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 61 61 62 63 64 65 65 66 67 68 69 69 6A 6B 6C 6D 6E 6F 6F 70 71 72 73 74 75 75 76 77 78 79 7A 61 55 }

	condition:
		all of them
}
