rule Windows_Generic_Threat_d51dd31b
{
	meta:
		author = "Elastic Security"
		id = "d51dd31b-1735-4fd7-9906-b07406a9d20c"
		fingerprint = "f313354a52ba8058c36aea696fde5548c7eb9211cac3b6caa511671445efe2a7"
		creation_date = "2024-01-24"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "2a61c0305d82b6b4180c3d817c28286ab8ee56de44e171522bd07a60a1d8492d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 7E 7D 7C 7B 7A 79 78 78 76 77 74 73 72 }
		$a2 = { 6D 6C 6B 6A 69 68 67 66 65 64 63 62 61 60 60 5E 66 60 5B 5A }

	condition:
		all of them
}
