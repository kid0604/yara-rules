rule Linux_Exploit_Vmsplice_431e689d
{
	meta:
		author = "Elastic Security"
		id = "431e689d-0c41-4c92-98b0-0dac529d8328"
		fingerprint = "1e8aee445a3adef6ccbd2d25f7b38202bef98a99b828eda56fb8b9269b6316b4"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Vmsplice"
		reference = "1cbb09223f16af4cd13545d72dbeeb996900535b1e279e4bcf447670728de1e1"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Exploit.Vmsplice"
		filetype = "executable"

	strings:
		$a = { 69 6F 6E 00 70 75 74 65 6E 76 00 73 74 64 6F 75 74 00 73 65 }

	condition:
		all of them
}
