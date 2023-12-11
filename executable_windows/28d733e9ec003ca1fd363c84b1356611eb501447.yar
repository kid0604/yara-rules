rule Windows_Trojan_Metasploit_91bc5d7d
{
	meta:
		author = "Elastic Security"
		id = "91bc5d7d-31e3-4c02-82b3-a685194981f3"
		fingerprint = "8848a3de66a25dd98278761a7953f31b7995e48621dec258f3d92bd91a4a3aa3"
		creation_date = "2021-08-02"
		last_modified = "2021-10-04"
		threat_name = "Windows.Trojan.Metasploit"
		reference_sample = "0dd993ff3917dc56ef02324375165f0d66506c5a9b9548eda57c58e041030987"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Metasploit variant 91bc5d7d"
		filetype = "executable"

	strings:
		$a = { 49 BE 77 73 32 5F 33 32 00 00 41 56 49 89 E6 48 81 EC A0 01 00 00 49 89 E5 }

	condition:
		all of them
}
