rule Windows_Trojan_Metasploit_2092c42a
{
	meta:
		author = "Elastic Security"
		id = "2092c42a-793b-4b0e-868b-9a39c926f44c"
		fingerprint = "4f17bfb02d3ac97e48449b6e30c9b07f604c13d5e12a99af322853c5d656ee88"
		creation_date = "2023-05-09"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.Metasploit"
		reference_sample = "e47d88c11a89dcc84257841de0c9f1ec388698006f55a0e15567354b33f07d3c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Metasploit with specific fingerprint"
		filetype = "executable"

	strings:
		$a1 = { 65 6E 61 62 6C 65 5F 6B 65 79 62 6F 61 72 64 5F 69 6E 70 75 74 }
		$a2 = { 01 04 10 49 83 C2 02 4D 85 C9 75 9C 41 8B 43 04 4C 03 D8 48 }

	condition:
		all of them
}
