rule Linux_Trojan_Metasploit_d74153f6
{
	meta:
		author = "Elastic Security"
		id = "d74153f6-0047-4576-8c3e-db0525bb3a92"
		fingerprint = "824baa1ee7fda8074d76e167d3c5cc1911c7224bb72b1add5e360f26689b48c2"
		creation_date = "2024-05-07"
		last_modified = "2024-05-21"
		description = "Detects x86 msfvenom IPv6 TCP reverse shells"
		threat_name = "Linux.Trojan.Metasploit"
		reference_sample = "2823d27492e2e7a95b67a08cb269eb6f4175451d58b098ae429330913397d40a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		filetype = "executable"

	strings:
		$str1 = { 31 DB 53 43 53 6A 0A 89 E1 6A 66 58 CD 80 96 99 }
		$str2 = { 89 E1 6A 1C 51 56 89 E1 43 43 6A 66 58 CD 80 89 F3 B6 0C B0 03 CD 80 89 DF }

	condition:
		all of them
}
