rule Windows_Trojan_CobaltStrike_8d5963a2
{
	meta:
		author = "Elastic Security"
		id = "8d5963a2-54a9-4705-9f34-0d5f8e6345a2"
		fingerprint = "228cd65380cf4b04f9fd78e8c30c3352f649ce726202e2dac9f1a96211925e1c"
		creation_date = "2022-08-10"
		last_modified = "2022-09-29"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "9fe43996a5c4e99aff6e2a1be743fedec35e96d1e6670579beb4f7e7ad591af9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan CobaltStrike 8d5963a2"
		filetype = "executable"

	strings:
		$a = { 40 55 53 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 D8 48 81 EC 28 01 00 00 45 33 F6 48 8B D9 48 }

	condition:
		all of them
}
