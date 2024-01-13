rule Windows_Generic_Threat_b1f6f662
{
	meta:
		author = "Elastic Security"
		id = "b1f6f662-ea77-4049-a58a-ed8a97d7738e"
		fingerprint = "f2cd22e34b4694f707ee9042805f5498ce66d35743950096271aaa170f44a2ee"
		creation_date = "2024-01-01"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "1b7eaef3cf1bb8021a00df092c829932cccac333990db1c5dac6558a5d906400"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 67 65 74 5F 4D 53 56 61 6C 75 65 31 30 }
		$a2 = { 73 65 74 5F 4D 53 56 61 6C 75 65 31 30 }
		$a3 = { 67 65 74 5F 4D 53 56 61 6C 75 65 31 31 }

	condition:
		all of them
}
