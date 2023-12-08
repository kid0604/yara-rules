rule Linux_Trojan_Meterpreter_a82f5d21
{
	meta:
		author = "Elastic Security"
		id = "a82f5d21-3b01-4a05-a34a-6985c1f3b460"
		fingerprint = "b0adb928731dc489a615fa86e46cc19de05e251eef2e02eb02f478ed1ca01ec5"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Meterpreter"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Meterpreter with specific fingerprint"
		filetype = "executable"

	strings:
		$a = { F8 02 74 22 77 08 66 83 F8 01 74 20 EB 24 66 83 F8 03 74 0C 66 83 }

	condition:
		all of them
}
