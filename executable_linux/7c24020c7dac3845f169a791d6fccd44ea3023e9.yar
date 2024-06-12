rule Linux_Generic_Threat_d94e1020
{
	meta:
		author = "Elastic Security"
		id = "d94e1020-ff66-4501-95e1-45ab552b1c18"
		fingerprint = "c291c07b6225c8ce94f38ad7cb8bb908039abfc43333c6524df776b28c79452a"
		creation_date = "2024-05-20"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "96a2bfbb55250b784e94b1006391cc51e4adecbdde1fe450eab53353186f6ff0"
		severity = 50
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic threat on Linux systems"
		filetype = "executable"

	strings:
		$a1 = { D0 4D E2 0C C0 9D E5 0C 30 4C E2 02 00 53 E3 14 30 8D E2 00 30 8D E5 10 30 9D E5 0C 10 A0 E1 03 20 A0 E1 01 00 00 8A 0F 00 00 EB 0A 00 00 EA 03 20 A0 E1 0C 10 A0 E1 37 00 90 EF 01 0A 70 E3 00 }

	condition:
		all of them
}
