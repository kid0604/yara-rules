rule Linux_Trojan_Metasploit_5d26689f
{
	meta:
		author = "Elastic Security"
		id = "5d26689f-3d3a-41f1-ac32-161b3b312b74"
		fingerprint = "b78fda9794dc24507405fc04bdc0a3e8abfcdc5c757787b7d9822f4ea2190120"
		creation_date = "2024-05-07"
		last_modified = "2024-05-21"
		description = "Detects x86 msfvenom bind TCP random port payloads"
		threat_name = "Linux.Trojan.Metasploit"
		reference_sample = "dafefb4d79d848384442a697b1316d93fef2741fca854be744896ce1d7f82073"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		filetype = "executable"

	strings:
		$tiny_bind = { 31 D2 52 68 2F 2F 73 68 68 2F 62 69 6E 68 2D 6C 65 2F 89 E7 52 68 2F 2F 6E 63 68 2F 62 69 6E 89 E3 52 57 53 89 E1 31 C0 B0 0B CD 80 }
		$reg_bind_setup = { 31 DB F7 E3 B0 66 43 52 53 6A 02 89 E1 CD 80 52 50 89 E1 B0 66 B3 04 CD 80 B0 66 43 CD 80 59 93 }
		$reg_bind_dup_loop = { 6A 3F 58 CD 80 49 79 }
		$reg_bind_execve = { B0 0B 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 41 CD 80 }

	condition:
		($tiny_bind) or ( all of ($reg_bind*))
}
