rule Linux_Trojan_Mirai_99d78950
{
	meta:
		author = "Elastic Security"
		id = "99d78950-ea23-4166-a85a-7a029209f5b1"
		fingerprint = "3008edc4e7a099b64139a77d15ec0e2c3c1b55fc23ab156304571c4d14bc654c"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "8dc745a6de6f319cd6021c3e147597315cc1be02099d78fc8aae94de0e1e4bc6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai"
		filetype = "executable"

	strings:
		$a = { 10 89 C3 80 BC 04 83 00 00 00 20 0F 94 C0 8D B4 24 83 00 00 00 25 FF 00 }

	condition:
		all of them
}
