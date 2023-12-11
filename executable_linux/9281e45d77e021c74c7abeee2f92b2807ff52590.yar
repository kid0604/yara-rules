rule Linux_Trojan_Rbot_c69475e3
{
	meta:
		author = "Elastic Security"
		id = "c69475e3-59eb-4d3c-9ee6-01ae7a3973d3"
		fingerprint = "593ff388ba10d66b97b5dfc9220bbda6b1584fe73d6bf7c1aa0f5391bb87e939"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Rbot"
		reference_sample = "9d97c69b65d2900c39ca012fe0486e6a6abceebb890cbb6d2e091bb90f6b9690"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Trojan.Rbot malware"
		filetype = "executable"

	strings:
		$a = { 56 8B 76 20 03 F5 33 C9 49 41 AD 33 DB 36 0F BE 14 28 38 F2 }

	condition:
		all of them
}
