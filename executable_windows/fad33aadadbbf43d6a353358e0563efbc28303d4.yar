rule Windows_Trojan_Metasploit_24338919
{
	meta:
		author = "Elastic Security"
		id = "24338919-8efe-4cf2-a23a-a3f22095b42d"
		fingerprint = "ac76190a84c4bdbb6927c5ad84a40e2145ca9e76369a25ac2ffd727eefef4804"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies metasploit wininet reverse shellcode. Also used by other tools (like beacon)."
		threat_name = "Windows.Trojan.Metasploit"
		severity = 80
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = { 68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 }

	condition:
		$a1
}
