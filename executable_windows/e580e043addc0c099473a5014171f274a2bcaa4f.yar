rule Windows_Ransomware_Lockbit_a1c60939
{
	meta:
		author = "Elastic Security"
		id = "a1c60939-e257-420d-87ed-f31f30f2fc2a"
		fingerprint = "a41fb21e82ee893468393428d655b03ce251d23f34acb54bbf01ae0eb86817bf"
		creation_date = "2021-08-06"
		last_modified = "2021-10-04"
		threat_name = "Windows.Ransomware.Lockbit"
		reference_sample = "0d6524b9a1d709ecd9f19f75fa78d94096e039b3d4592d13e8dbddf99867182d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Ransomware Lockbit"
		filetype = "executable"

	strings:
		$a1 = { 3C 8B 4C 18 78 8D 04 19 89 45 F8 3B C3 74 70 33 C9 89 4D F4 39 }

	condition:
		all of them
}
