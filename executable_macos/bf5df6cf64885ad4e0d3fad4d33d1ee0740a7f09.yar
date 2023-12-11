rule MacOS_Trojan_Metasploit_5e5b685f
{
	meta:
		author = "Elastic Security"
		id = "5e5b685f-1b6b-4102-b54d-91318e418c6c"
		fingerprint = "52c41d4fc4d195e702523dd2b65e4078dd967f9c4e4b1c081bc04d88c9e4804f"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Metasploit"
		reference_sample = "cdf0a3c07ef1479b53d49b8f22a9f93adcedeea3b869ef954cc043e54f65c3d0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Metasploit"
		filetype = "executable"

	strings:
		$a1 = { 00 00 F4 90 90 90 90 55 48 89 E5 48 81 EC 60 20 00 00 89 F8 48 8B 0D 74 23 00 }

	condition:
		all of them
}
