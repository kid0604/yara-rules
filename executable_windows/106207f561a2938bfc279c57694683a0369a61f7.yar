rule Windows_Trojan_Metasploit_66140f58
{
	meta:
		author = "Elastic Security"
		id = "66140f58-1815-4e21-8544-24fed74194f1"
		fingerprint = "79879b2730e98f3eddeca838dff438d75a43ac20c0da6a4802474ff05f9cc7a3"
		creation_date = "2022-08-15"
		last_modified = "2022-09-29"
		threat_name = "Windows.Trojan.Metasploit"
		reference_sample = "01a0c5630fbbfc7043d21a789440fa9dadc6e4f79640b370f1a21c6ebf6a710a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Metasploit"
		filetype = "executable"

	strings:
		$a = { FC 48 83 E4 F0 E8 CC 00 00 00 41 51 41 50 52 48 31 D2 51 65 48 8B 52 60 48 8B 52 18 48 8B 52 20 }

	condition:
		all of them
}
