rule Linux_Trojan_Mirai_8aa7b5d3
{
	meta:
		author = "Elastic Security"
		id = "8aa7b5d3-e1eb-4b55-b36a-0d3a242c06e9"
		fingerprint = "02a2c18c362df4b1fceb33f3b605586514ba9a00c7afedf71c04fa54d8146444"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "5217f2a46cb93946e04ab00e385ad0fe0a2844b6ea04ef75ee9187aac3f3d52f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Mirai variant 8aa7b5d3"
		filetype = "executable"

	strings:
		$a = { 8B 4C 24 14 8B 74 24 0C 8B 5C 24 10 85 C9 74 0D 31 D2 8A 04 1A 88 }

	condition:
		all of them
}
