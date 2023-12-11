rule Windows_Ransomware_Ragnarok_7e802f95 : beta
{
	meta:
		author = "Elastic Security"
		id = "7e802f95-964e-4dd9-a5d1-13a6cd73d750"
		fingerprint = "c62b3706a2024751f1346d0153381ac28057995cf95228e43affc3d1e4ad0fad"
		creation_date = "2020-05-03"
		last_modified = "2021-08-23"
		description = "Identifies RAGNAROK ransomware"
		threat_name = "Windows.Ransomware.Ragnarok"
		reference = "https://twitter.com/malwrhunterteam/status/1256263426441125888?s=20"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$d1 = { 68 04 94 42 00 FF 35 A0 77 43 00 }
		$d2 = { 68 90 94 42 00 FF 35 A0 77 43 00 E8 8F D6 00 00 8B 40 10 50 }

	condition:
		1 of ($d*)
}
