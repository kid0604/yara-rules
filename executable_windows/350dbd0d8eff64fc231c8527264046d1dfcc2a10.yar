rule Windows_Trojan_Metasploit_0f5a852d
{
	meta:
		author = "Elastic Security"
		id = "0f5a852d-cacd-43d7-8754-204b09afba2f"
		fingerprint = "97daac4249e85a73d4e6a4450248e59e0d286d5e7c230cf32a38608f8333f00d"
		creation_date = "2021-04-07"
		last_modified = "2021-08-23"
		description = "Identifies 64 bit metasploit wininet reverse shellcode. May also be used by other malware families."
		threat_name = "Windows.Trojan.Metasploit"
		severity = 80
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a = { 49 BE 77 69 6E 69 6E 65 74 00 41 56 48 89 E1 49 C7 C2 4C 77 26 07 FF D5 }

	condition:
		all of them
}
