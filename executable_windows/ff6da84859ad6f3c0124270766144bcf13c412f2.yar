rule Windows_Trojan_Smokeloader_4e31426e
{
	meta:
		author = "Elastic Security"
		id = "4e31426e-d62e-4b6d-911b-4223e1f6adef"
		fingerprint = "cf6d8615643198bc53527cb9581e217f8a39760c2e695980f808269ebe791277"
		creation_date = "2021-07-21"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Smokeloader"
		reference_sample = "1ce643981821b185b8ad73b798ab5c71c6c40e1f547b8e5b19afdaa4ca2a5174"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Smokeloader variant"
		filetype = "executable"

	strings:
		$a = { 5B 81 EB 34 10 00 00 6A 30 58 64 8B 00 8B 40 0C 8B 40 1C 8B 40 08 89 85 C0 }

	condition:
		all of them
}
