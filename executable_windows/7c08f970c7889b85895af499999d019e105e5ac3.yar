rule Windows_Trojan_CyberGate_c219a2f3
{
	meta:
		author = "Elastic Security"
		id = "c219a2f3-5ae2-4cdf-97d7-2778954ee826"
		fingerprint = "8a79d1eba89dd08d2e8bdedee834c88dbeabf5f2f249b1e5accdb827671c22c2"
		creation_date = "2023-05-04"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.CyberGate"
		reference_sample = "b7204f8caf6ace6ae1aed267de0ad6b39660d0e636d8ee0ecf88135f8a58dc42"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan CyberGate"
		filetype = "executable"

	strings:
		$a1 = { 00 00 55 8B EC 83 C4 EC 56 57 8B 45 08 8B F0 8D 7D EC A5 A5 }
		$a2 = { 49 80 39 C3 75 F5 8B C2 C3 55 8B EC 6A 00 6A 00 6A 00 53 56 57 }

	condition:
		all of them
}
