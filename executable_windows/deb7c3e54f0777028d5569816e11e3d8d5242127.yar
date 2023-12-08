rule Windows_Trojan_MicroBackdoor_903e33c3
{
	meta:
		author = "Elastic Security"
		id = "903e33c3-d8f1-4c3b-900b-7503edb11951"
		fingerprint = "06b3c0164c2d06f50d1e6ae0a9edf823ae1fef53574e0d20020aada8721dfee0"
		creation_date = "2022-03-07"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.MicroBackdoor"
		reference_sample = "fbbfcc81a976b57739ef13c1545ea4409a1c69720469c05ba249a42d532f9c21"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan MicroBackdoor"
		filetype = "executable"

	strings:
		$a = { 55 8B EC 83 EC 1C 56 57 E8 33 01 00 00 8B F8 85 FF 74 48 BA 26 80 AC C8 8B CF E8 E1 01 00 00 BA }

	condition:
		all of them
}
