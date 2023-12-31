rule Windows_Trojan_CyberGate_9996d800
{
	meta:
		author = "Elastic Security"
		id = "9996d800-a833-4535-972b-3ee320215bb6"
		fingerprint = "eb39d2ff211230aedcf1b5ec0d1dfea108473cc7cba68f5dc1a88479734c02b0"
		creation_date = "2022-02-28"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.CyberGate"
		reference_sample = "07b8f25e7b536f5b6f686c12d04edc37e11347c8acd5c53f98a174723078c365"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan CyberGate"
		filetype = "executable"

	strings:
		$a1 = { 24 08 8B 44 24 08 83 C4 14 5D 5F 5E 5B C3 55 8B EC 83 C4 F0 }

	condition:
		all of them
}
