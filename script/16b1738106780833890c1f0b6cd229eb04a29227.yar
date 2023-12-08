rule MacOS_Trojan_Metasploit_7ce0b709
{
	meta:
		author = "Elastic Security"
		id = "7ce0b709-1d96-407c-8eca-6af64e5bdeef"
		fingerprint = "3eb7f78d2671e16c16a6d9783995ebb32e748612d32ed4f2442e9f9c1efc1698"
		creation_date = "2021-09-30"
		last_modified = "2021-10-25"
		description = "Byte sequence based on Metasploit shell_bind_tcp.rb"
		threat_name = "MacOS.Trojan.Metasploit"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/shell_bind_tcp.rb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		filetype = "script"

	strings:
		$a1 = { FF 4F E4 79 F6 50 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 }

	condition:
		all of them
}
