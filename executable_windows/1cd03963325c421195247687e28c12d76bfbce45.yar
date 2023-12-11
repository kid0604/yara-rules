rule Windows_Trojan_Amadey_c4df8d4a
{
	meta:
		author = "Elastic Security"
		id = "c4df8d4a-01f4-466f-8225-7c7f462b29e7"
		fingerprint = "4623c591ea465e23f041db77dc68ddfd45034a8bde0f20fd5fbcec060851200c"
		creation_date = "2021-06-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Amadey"
		reference_sample = "9039d31d0bd88d0c15ee9074a84f8d14e13f5447439ba80dd759bf937ed20bf2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Amadey"
		filetype = "executable"

	strings:
		$a1 = "D:\\Mktmp\\NL1\\Release\\NL1.pdb" fullword

	condition:
		all of them
}
