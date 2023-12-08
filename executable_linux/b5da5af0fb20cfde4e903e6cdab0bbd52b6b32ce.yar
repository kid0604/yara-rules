rule Linux_Hacktool_Flooder_53bf4e37
{
	meta:
		author = "Elastic Security"
		id = "53bf4e37-e043-4cf2-ad2a-bc63d69585ae"
		fingerprint = "83e804640b0848caa532dadc33923c226a34e0272457bde00325069ded55f256"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference = "101f2240cd032831b9c0930a68ea6f74688f68ae801c776c71b488e17bc71871"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 74 00 49 50 5F 48 44 52 49 4E 43 4C 00 57 68 61 74 20 74 68 65 20 }

	condition:
		all of them
}
