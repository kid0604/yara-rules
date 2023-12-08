rule Linux_Trojan_Mirai_d2205527
{
	meta:
		author = "Elastic Security"
		id = "d2205527-0545-462b-b3c9-3bf2bdc44c6c"
		fingerprint = "01d937fe8823e5f4764dea9dfe2d8d789187dcd6592413ea48e13f41943d67fd"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "e4f584d1f75f0d7c98b325adc55025304d55907e8eb77b328c007600180d6f06"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { CA B8 37 00 00 00 0F 05 48 3D 01 F0 FF FF 73 01 C3 48 C7 C1 C0 FF }

	condition:
		all of them
}
