rule Linux_Trojan_Xorddos_2522d611
{
	meta:
		author = "Elastic Security"
		id = "2522d611-4ce3-4583-87d6-e5631b62d562"
		fingerprint = "985885a6b5f01e8816027f92148d2496a5535f3c15de151f05f69ec273291506"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "0c2be53e298c285db8b028f563e97bf1cdced0c4564a34e740289b340db2aac1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Xorddos"
		filetype = "executable"

	strings:
		$a = { 24 04 57 8B 7C 24 02 5F 87 44 24 00 50 8B 44 24 04 8D 40 42 87 44 }

	condition:
		all of them
}
