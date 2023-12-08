rule Windows_Ransomware_Blackmatter_8394f6d5
{
	meta:
		author = "Elastic Security"
		id = "8394f6d5-4761-4df6-974d-eaa0a25353da"
		fingerprint = "3825f59ffe9b2adc1f9dd175f4d57c9aa3dd6ff176616ecbe7c673b5b4d414f8"
		creation_date = "2021-08-03"
		last_modified = "2021-10-04"
		threat_name = "Windows.Ransomware.Blackmatter"
		reference_sample = "072158f5588440e6c94cb419ae06a27cf584afe3b0cb09c28eff0b4662c15486"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Ransomware Blackmatter variant 8394f6d5"
		filetype = "executable"

	strings:
		$a1 = { FF E1 D7 66 8C 41 03 EB F8 64 E5 7E F1 06 73 AB BF 6B 1D 6A B9 B6 BA 41 A2 91 49 5E 85 51 A0 83 23 }

	condition:
		any of them
}
