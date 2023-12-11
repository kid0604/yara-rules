rule Linux_Exploit_Cornelgen_be0bc02d
{
	meta:
		author = "Elastic Security"
		id = "be0bc02d-2d9d-4cbe-9d6a-3a88ffa1234b"
		fingerprint = "6b57eb6fd3c8e28cbff5e7cc51246de74ca7111a9cd1c795b21aa89142a693b4"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Cornelgen"
		reference_sample = "24c0ba8ad4f543f9b0aff0d0b66537137bc78606b47ced9b6d08039bbae78d80"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the Linux.Exploit.Cornelgen malware"
		filetype = "executable"

	strings:
		$a = { 8B 44 24 08 A3 B8 9F 04 08 0F B7 05 04 A1 04 08 }

	condition:
		all of them
}
