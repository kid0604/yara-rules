rule Windows_Trojan_IcedID_2086aecb
{
	meta:
		author = "Elastic Security"
		id = "2086aecb-161b-4102-89c7-580fb9ac3759"
		fingerprint = "a8b6cbb3140ff3e1105bb32a2da67831917caccc4985c485bbfdb0aa50016d86"
		creation_date = "2022-04-06"
		last_modified = "2022-03-02"
		threat_name = "Windows.Trojan.IcedID"
		reference_sample = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan IcedID variant 2086aecb"
		filetype = "executable"

	strings:
		$a = { 4C 8D 05 [4] 42 8A 44 01 ?? 42 32 04 01 88 44 0D ?? 48 FF C1 48 83 F9 20 72 ?? }

	condition:
		all of them
}
