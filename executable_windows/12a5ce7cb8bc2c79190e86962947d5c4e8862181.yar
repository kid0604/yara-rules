rule Windows_Generic_Threat_e7eaa4ca
{
	meta:
		author = "Elastic Security"
		id = "e7eaa4ca-45ee-42ea-9604-d9d569eed0aa"
		fingerprint = "ede23e801a67bc43178eea87a83eb0ef32a74d48476a8273a25a7732af6f22a6"
		creation_date = "2024-01-04"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a = { C8 F7 C6 A8 13 F7 01 E9 2C 99 08 00 4C 03 D1 E9 }

	condition:
		all of them
}
