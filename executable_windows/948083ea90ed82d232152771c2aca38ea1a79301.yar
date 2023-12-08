rule Windows_Trojan_Metasploit_b29fe355
{
	meta:
		author = "Elastic Security"
		id = "b29fe355-b7f8-4325-bf06-7975585f3888"
		fingerprint = "a943325b7a227577ccd45748b4e705288c5b7d91d0e0b2a115daeea40e1a2148"
		creation_date = "2022-06-08"
		last_modified = "2022-09-29"
		threat_name = "Windows.Trojan.Metasploit"
		reference_sample = "4f0ab4e42e6c10bc9e4a699d8d8819b04c17ed1917047f770dc6980a0a378a68"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Metasploit"
		filetype = "executable"

	strings:
		$a1 = "%04x-%04x:%s" fullword
		$a2 = "\\\\%s\\pipe\\%s" fullword
		$a3 = "PACKET TRANSMIT" fullword

	condition:
		all of them
}
