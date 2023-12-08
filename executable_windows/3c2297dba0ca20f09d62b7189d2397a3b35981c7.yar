rule Windows_Trojan_Metasploit_a6e956c9
{
	meta:
		author = "Elastic Security"
		id = "a6e956c9-799e-49f9-b5c5-ac68aaa2dc21"
		fingerprint = "21855599bc51ec2f71d694d4e0f866f815efe54a42842dfe5f8857811530a686"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies the API address lookup function leverage by metasploit shellcode"
		threat_name = "Windows.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = { 60 89 E5 31 C0 64 8B 50 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF AC 3C 61 7C 02 2C 20 }

	condition:
		$a1
}
