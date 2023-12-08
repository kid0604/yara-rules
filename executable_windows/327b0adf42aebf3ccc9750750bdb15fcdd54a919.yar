rule Windows_Trojan_Havoc_9c7bb863
{
	meta:
		author = "Elastic Security"
		id = "9c7bb863-b6c2-4d5f-ae50-0fd900f1d4eb"
		fingerprint = "cda55a9e65badb984e71778b081929db2bdef223792b78bba32b2259757f1348"
		creation_date = "2023-04-28"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.Havoc"
		reference_sample = "261b92d9e8dcb9d0abf1627b791831ec89779f2b7973b1926c6ec9691288dd57"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Havoc"
		filetype = "executable"

	strings:
		$a1 = { 56 48 89 E6 48 83 E4 F0 48 83 EC 20 E8 0F 00 00 00 48 89 F4 5E C3 }
		$a2 = { 65 48 8B 04 25 60 00 00 00 }

	condition:
		all of them
}
