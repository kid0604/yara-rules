rule Windows_Trojan_Glupteba_4669dcd6
{
	meta:
		author = "Elastic Security"
		id = "4669dcd6-8e04-416d-91c0-f45816430869"
		fingerprint = "5b598640f42a99b00d481031f5fcf143ffcc32ef002eac095a14edb18d5b02c9"
		creation_date = "2021-08-08"
		last_modified = "2021-10-04"
		threat_name = "Windows.Trojan.Glupteba"
		reference_sample = "1b55042e06f218546db5ddc52d140be4303153d592dcfc1ce90e6077c05e77f7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Glupteba with ID 4669dcd6"
		filetype = "executable"

	strings:
		$a1 = { 40 C3 8B 44 24 48 8B 4C 24 44 89 81 AC 00 00 00 8B 44 24 4C 89 81 B0 00 }

	condition:
		all of them
}
