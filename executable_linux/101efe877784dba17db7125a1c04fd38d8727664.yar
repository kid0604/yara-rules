rule Linux_Trojan_Metasploit_b957e45d
{
	meta:
		author = "Elastic Security"
		id = "b957e45d-0eb6-4580-af84-98608bbc34ef"
		fingerprint = "ac71352e2b4c8ee8917b1469cd33e6b54eb4cdcd96f02414465127c5cad6b710"
		creation_date = "2024-05-07"
		last_modified = "2024-05-21"
		description = "Detects x86 msfvenom nonx TCP reverse shells"
		threat_name = "Linux.Trojan.Metasploit"
		reference_sample = "78af84bad4934283024f4bf72dfbf9cc081d2b92a9de32cc36e1289131c783ab"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		filetype = "executable"

	strings:
		$str1 = { 31 DB 53 43 53 6A 02 6A 66 58 89 E1 CD 80 97 5B }
		$str2 = { 66 53 89 E1 6A 66 58 50 51 57 89 E1 43 CD 80 5B 99 B6 0C B0 03 CD 80 }

	condition:
		all of them
}
