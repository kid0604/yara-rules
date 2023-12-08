rule Windows_Trojan_Metasploit_46e1c247
{
	meta:
		author = "Elastic Security"
		id = "46e1c247-1ebb-434f-835f-faf421b35169"
		fingerprint = "6cd37d32976add38d7165f8088f38f4854b59302d6adf20db5c46cd3e8c7d9e7"
		creation_date = "2023-05-10"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.Metasploit"
		reference_sample = "ef70e1faa3b1f40d92b0a161c96e13c96c43ec6651e7c87ee3977ed07b950bab"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Metasploit"
		filetype = "executable"

	strings:
		$a1 = { 73 74 64 61 70 69 5F 66 73 5F 66 69 6C 65 }
		$a2 = { 85 D2 74 0E 8B F3 2B 75 F8 8A 01 88 04 0E 41 4A 75 F7 0F B7 }

	condition:
		all of them
}
