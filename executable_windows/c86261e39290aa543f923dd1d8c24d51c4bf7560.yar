rule Windows_Generic_Threat_2bb6f41d
{
	meta:
		author = "Elastic Security"
		id = "2bb6f41d-41bb-4257-84ef-9026fcc0ebec"
		fingerprint = "d9062e792a0b8f92a03c0fdadd4dd651a0072faa3dd439bb31399a0c75a78c21"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "afa060352346dda4807dffbcac75bf07e8800d87ff72971b65e9805fabef39c0"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 67 65 74 5F 73 45 78 70 59 65 61 72 }
		$a2 = { 73 65 74 5F 73 45 78 70 59 65 61 72 }
		$a3 = { 42 72 6F 77 73 65 72 50 61 74 68 54 6F 41 70 70 4E 61 6D 65 }

	condition:
		all of them
}
