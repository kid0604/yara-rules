rule Linux_Trojan_Tsunami_ad60d7e8
{
	meta:
		author = "Elastic Security"
		id = "ad60d7e8-0823-4bfa-b823-681c554bf297"
		fingerprint = "e1ca4c566307238a5d8cd16db8d0d528626e0b92379177b167ce25b4c88d10ce"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Trojan.Tsunami malware"
		filetype = "executable"

	strings:
		$a = { 4E 4F 54 49 43 45 20 25 73 20 3A 53 70 6F 6F 66 73 3A 20 25 64 2E 25 64 2E 25 64 2E 25 64 }

	condition:
		all of them
}
