rule Linux_Trojan_Kinsing_2c1ffe78
{
	meta:
		author = "Elastic Security"
		id = "2c1ffe78-a965-4a70-8a9c-2cad705f8be7"
		fingerprint = "6701b007ee14a022525301d53af0f4254bc26fdfbe27d3d5cebc2d40e8536ed6"
		creation_date = "2021-12-13"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Kinsing"
		reference_sample = "b3527e3d03a30fcf1fdaa73a1b3743866da6db088fbfa5f51964f519e22d05e6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Kinsing"
		filetype = "executable"

	strings:
		$a = { 73 74 73 20 22 24 42 49 4E 5F 46 55 4C 4C 5F 50 41 54 48 22 20 22 }

	condition:
		all of them
}
