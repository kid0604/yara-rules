rule MacOS_Trojan_Thiefquest_40f9c1c3
{
	meta:
		author = "Elastic Security"
		id = "40f9c1c3-29f8-4699-8f66-9b7ddb08f92d"
		fingerprint = "27ec200781541d5b1abc96ffbb54c428b773bffa0744551bbacd605c745b6657"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Thiefquest"
		reference_sample = "e402063ca317867de71e8e3189de67988e2be28d5d773bbaf75618202e80f9f6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Thiefquest"
		filetype = "executable"

	strings:
		$a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 33 7C 49 56 7C 6A 30 30 }

	condition:
		all of them
}
