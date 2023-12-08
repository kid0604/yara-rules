rule Linux_Trojan_Sshdoor_7c3cfc62
{
	meta:
		author = "Elastic Security"
		id = "7c3cfc62-aa90-4c28-b428-e2133a3f10f8"
		fingerprint = "8085c47704b4d6cabad9d1dd48034dc224f725ba22a7872db50c709108bf575d"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Sshdoor"
		reference_sample = "ee1f6dbea40d198e437e8c2ae81193472c89e41d1998bee071867dab1ce16b90"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Sshdoor"
		filetype = "executable"

	strings:
		$a = { 55 48 8D 6F 50 53 49 89 FC 48 89 FB 48 83 EC 10 64 48 8B 04 25 28 00 }

	condition:
		all of them
}
