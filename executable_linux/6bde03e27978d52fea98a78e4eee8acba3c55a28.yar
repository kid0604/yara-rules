rule Linux_Trojan_Mirai_7d05725e
{
	meta:
		author = "Elastic Security"
		id = "7d05725e-db59-42a7-99aa-99de79728126"
		fingerprint = "7fcd34cb7c37836a1fa8eb9375a80da01bda0e98c568422255d83c840acc0714"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "fc8741f67f39e7409ab2c6c62d4f9acdd168d3e53cf6976dd87501833771cacb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with ID 7d05725e"
		filetype = "executable"

	strings:
		$a = { 24 97 00 00 00 89 6C 24 08 89 74 24 04 89 14 24 0F B7 C0 89 44 }

	condition:
		all of them
}
