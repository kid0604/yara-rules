rule Linux_Trojan_Meterpreter_1bda891e
{
	meta:
		author = "Elastic Security"
		id = "1bda891e-a031-4254-9d0b-dc590023d436"
		fingerprint = "fc3f5afb9b90bbf3b61f144f90b02ff712f60fbf62fb0c79c5eaa808627aa0a1"
		creation_date = "2021-12-13"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Meterpreter"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Meterpreter with fingerprint 1bda891e"
		filetype = "executable"

	strings:
		$a = { 11 62 08 F2 0F 5E D0 F2 0F 58 CB F2 0F 11 5A 10 F2 44 0F 5E C0 F2 0F }

	condition:
		all of them
}
