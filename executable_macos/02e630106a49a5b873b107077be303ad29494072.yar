rule MacOS_Trojan_Thiefquest_86f9ef0c
{
	meta:
		author = "Elastic Security"
		id = "86f9ef0c-832e-4e4a-bd39-c80c1d064dbe"
		fingerprint = "e8849628ee5449c461f1170c07b6d2ebf4f75d48136f26b52bee9bcf4e164d5b"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Thiefquest"
		reference_sample = "59fb018e338908eb69be72ab11837baebf8d96cdb289757f1f4977228e7640a0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Thiefquest"
		filetype = "executable"

	strings:
		$a = { 6C 65 31 6A 6F 57 4E 33 30 30 30 30 30 33 33 00 30 72 7A 41 43 47 33 57 72 7C }

	condition:
		all of them
}
