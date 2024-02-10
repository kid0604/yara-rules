rule Windows_Generic_Threat_66142106
{
	meta:
		author = "Elastic Security"
		id = "66142106-d602-4b1b-a79b-64d692c613ca"
		fingerprint = "b5816297691fefc46ab11cb175a4e20d40c5095c20417e80590ceb05bd1ec974"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "cd164a65fb2a496ad7b54c782f25fbfca0540d46d2c0d6b098d7be516c4ce021"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 EC 10 6A 00 8D 4D F0 E8 6B FF FF FF 8B 45 F4 BA E9 FD 00 00 39 50 08 74 0C E8 29 48 00 00 33 D2 85 C0 75 01 42 80 7D FC 00 74 0A 8B 4D F0 83 A1 50 03 00 00 FD 8B C2 C9 C3 8B FF 56 }

	condition:
		all of them
}
