rule Windows_Trojan_RedLineStealer_15ee6903
{
	meta:
		author = "Elastic Security"
		id = "15ee6903-757f-462b-8e1c-1ed8ca667910"
		fingerprint = "d3a380f68477b98b3f5adc11cc597042aa95636cfec0b0a5f2e51c201aa61227"
		creation_date = "2023-05-04"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "46b506cafb2460ca2969f69bcb0ee0af63b6d65e6b2a6249ef7faa21bde1a6bd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan RedLineStealer"
		filetype = "executable"

	strings:
		$a1 = { 53 65 65 6E 42 65 66 6F 72 65 33 }
		$a2 = { 73 65 74 5F 53 63 61 6E 47 65 63 6B 6F 42 72 6F 77 73 65 72 73 50 61 74 68 73 }

	condition:
		all of them
}
