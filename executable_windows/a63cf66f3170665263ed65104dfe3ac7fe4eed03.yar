rule Windows_Trojan_Metasploit_7bc0f998
{
	meta:
		author = "Elastic Security"
		id = "7bc0f998-7014-4883-8a56-d5ee00c15aed"
		fingerprint = "fdb5c665503f07b2fc1ed7e4e688295e1222a500bfb68418661db60c8e75e835"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies the API address lookup function leverage by metasploit shellcode"
		threat_name = "Windows.Trojan.Metasploit"
		severity = 84
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = { 48 31 D2 65 48 8B 52 60 48 8B 52 18 48 8B 52 20 48 8B 72 50 48 0F B7 4A 4A 4D 31 C9 48 31 C0 AC 3C 61 }

	condition:
		$a1
}
