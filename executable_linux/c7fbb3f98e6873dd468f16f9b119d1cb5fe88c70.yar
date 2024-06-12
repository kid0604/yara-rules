rule Linux_Generic_Threat_a3c5f3bd
{
	meta:
		author = "Elastic Security"
		id = "a3c5f3bd-9afe-44f4-98da-6ad704d0dee1"
		fingerprint = "f86d540c4e884a9c893471cf08db86c9bf34162fe9970411f8e56917fd9d3d8f"
		creation_date = "2024-05-21"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "8c093bcf3d83545ec442519637c956d2af62193ea6fd2769925cacda54e672b6"
		severity = 50
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 66 68 5F 72 65 6D 6F 76 65 5F 68 6F 6F 6B }
		$a2 = { 66 68 5F 66 74 72 61 63 65 5F 74 68 75 6E 6B }
		$a3 = { 66 68 5F 69 6E 73 74 61 6C 6C 5F 68 6F 6F 6B }

	condition:
		all of them
}
