rule MacOS_Trojan_Metasploit_d9b16f4c
{
	meta:
		author = "Elastic Security"
		id = "d9b16f4c-8cc9-42ce-95fa-8db06df9d582"
		fingerprint = "cf5cfc372008ae98a0958722a7b23f576d6be3b5b07214d21594a48a87d92fca"
		creation_date = "2021-09-30"
		last_modified = "2021-10-25"
		description = "Byte sequence based on Metasploit vforkshell_bind_tcp.rb"
		threat_name = "MacOS.Trojan.Metasploit"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/vforkshell_bind_tcp.rb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		filetype = "script"

	strings:
		$a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 0F 82 7E 00 00 00 89 C6 52 52 52 68 00 02 34 12 89 E3 6A }

	condition:
		all of them
}
