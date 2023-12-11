rule Windows_Trojan_Matanbuchus_4ce9affb
{
	meta:
		author = "Elastic Security"
		id = "4ce9affb-58ef-4d31-b1ff-5a1c52822a01"
		fingerprint = "61d32df2ea730343ab497f50d250712e89ec942733c8cc4421083a3823ab9435"
		creation_date = "2022-03-17"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Matanbuchus"
		reference_sample = "4eb85a5532b98cbc4a6db1697cf46b9e2b7e28e89d6bbfc137b36c0736cd80e2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Matanbuchus"
		filetype = "executable"

	strings:
		$a1 = { F4 83 7D F4 00 77 43 72 06 83 7D F0 11 73 3B 6A 00 6A 01 8B }

	condition:
		all of them
}
