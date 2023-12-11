rule Windows_Ransomware_Snake_119f9c83 : beta
{
	meta:
		author = "Elastic Security"
		id = "119f9c83-4b55-47ce-8c0d-3799a7b46369"
		fingerprint = "13ffd63c31df2cbaa6988abcaff3b0a3518437f1d37dcd872817b9cbdb61576f"
		creation_date = "2020-06-30"
		last_modified = "2021-08-23"
		description = "Identifies SNAKE ransomware"
		threat_name = "Windows.Ransomware.Snake"
		reference = "https://labs.sentinelone.com/new-snake-ransomware-adds-itself-to-the-increasing-collection-of-golang-crimeware/"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$c1 = { 00 40 83 7C 00 40 9E 7C 00 60 75 7C 00 B0 6C 7C 00 B0 74 7C 00 D0 74 7C 00 B0 59 7C 00 D0 59 7C 00 F0 59 7C 00 10 5A 7C 00 30 5A 7C 00 50 5A 7C 00 70 5A 7C 00 90 5A 7C 00 B0 5A 7C 00 D0 5A 7C 00 D0 6C 7C 00 F0 5A 7C 00 30 5B 7C 00 50 5B 7C 00 70 5B 7C 00 90 5B 7C 00 D0 5E 7C 00 B0 5B 7C 00 D0 5B 7C 00 F0 5B 7C 00 50 60 7C 00 70 61 7C 00 10 5C 7C 00 30 5C 7C 00 50 5C 7C 00 10 63 7C 00 70 5C 7C 00 90 5C 7C 00 90 64 7C 00 B0 5C 7C 00 F0 5C 7C 00 10 5D 7C 00 F0 6C 7C 00 10 6D 7C 00 30 5D 7C 00 50 5D 7C 00 30 6D 7C 00 90 71 7C 00 70 5D 7C 00 90 5D 7C 00 B0 5D 7C 00 D0 5D 7C 00 70 6D 7C 00 F0 5D 7C 00 10 5E 7C 00 30 5E 7C 00 50 5E 7C 00 70 5E 7C 00 90 5E 7C 00 B0 5E 7C 00 F0 5E 7C 00 10 5F 7C 00 30 5F 7C 00 50 5F 7C 00 70 5F 7C 00 90 6D 7C 00 90 5F 7C 00 B0 6D 7C 00 D0 6D 7C 00 F0 6D 7C 00 10 6E 7C 00 B0 5F 7C 00 D0 5F 7C 00 F0 5F 7C 00 10 60 7C 00 30 60 7C 00 30 6E 7C 00 70 60 7C }
		$c2 = { 00 30 64 7C 00 50 64 7C 00 70 64 7C 00 B0 64 7C 00 D0 64 7C 00 30 73 7C 00 F0 64 7C 00 90 71 7C 00 10 65 7C 00 30 65 7C 00 50 65 7C 00 90 72 7C 00 B0 72 7C 00 70 6E 7C 00 70 65 7C 00 B0 65 7C 00 D0 65 7C 00 F0 65 7C 00 10 66 7C 00 30 66 7C 00 50 66 7C 00 70 66 7C 00 90 66 7C 00 B0 66 7C 00 D0 66 7C 00 F0 66 7C 00 30 67 7C 00 90 6E 7C 00 B0 6E 7C 00 D0 6E 7C }

	condition:
		1 of ($c*)
}
