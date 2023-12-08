rule MacOS_Trojan_Metasploit_768df39d
{
	meta:
		author = "Elastic Security"
		id = "768df39d-7ee9-454e-82f8-5c7bd733c61a"
		fingerprint = "d45230c1111bda417228e193c8657d2318b1d2cddfbd01c5c6f2ea1d0be27a46"
		creation_date = "2021-09-30"
		last_modified = "2021-10-25"
		description = "Byte sequence based on Metasploit shell_reverse_tcp.rb"
		threat_name = "MacOS.Trojan.Metasploit"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_reverse_tcp.rb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		filetype = "script"

	strings:
		$a1 = { FF 4F E8 79 F6 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 }

	condition:
		all of them
}
