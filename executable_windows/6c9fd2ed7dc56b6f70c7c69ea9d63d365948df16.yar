rule Windows_Trojan_AgentTesla_a2d69e48
{
	meta:
		author = "Elastic Security"
		id = "a2d69e48-b114-4128-8c2f-6fabee49e152"
		fingerprint = "bd46dd911aadf8691516a77f3f4f040e6790f36647b5293050ecb8c25da31729"
		creation_date = "2023-05-01"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.AgentTesla"
		reference_sample = "edef51e59d10993155104d90fcd80175daa5ade63fec260e3272f17b237a6f44"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan AgentTesla"
		filetype = "executable"

	strings:
		$a1 = { 00 03 08 08 10 08 10 18 09 00 04 08 18 08 10 08 10 18 0E 00 08 }
		$a2 = { 00 06 17 5F 16 FE 01 16 FE 01 2A 00 03 30 03 00 B1 00 00 00 }

	condition:
		all of them
}
