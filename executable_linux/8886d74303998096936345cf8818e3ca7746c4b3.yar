rule Linux_Trojan_Meterpreter_621054fe
{
	meta:
		author = "Elastic Security"
		id = "621054fe-bbdf-445c-a503-ccba82b88243"
		fingerprint = "13cb03783b1d5f14cadfaa9b938646d5edb30ea83702991a81cc4ca82e4637dc"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Meterpreter"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Meterpreter"
		filetype = "executable"

	strings:
		$a = { 28 85 D2 75 0A 8B 50 2C 83 C8 FF 85 D2 74 03 8B 42 64 5D C3 55 }

	condition:
		all of them
}
