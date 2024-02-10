rule Windows_Generic_Threat_bbf2a354
{
	meta:
		author = "Elastic Security"
		id = "bbf2a354-64e5-4115-aaf7-2705194445da"
		fingerprint = "8fb9fcf8b9c661e4966b37a107d493e620719660295b200cfc67fc5533489dee"
		creation_date = "2024-01-22"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "b4e6c748ad88070e39b53a9373946e9e404623326f710814bed439e5ea61fc3e"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 54 68 61 74 20 70 72 6F 67 72 61 6D 20 6D 75 73 74 20 62 65 20 72 75 6E 20 75 6E 64 65 72 20 57 69 6E 33 32 }

	condition:
		all of them
}
