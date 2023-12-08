rule MacOS_Trojan_Metasploit_27d409f1
{
	meta:
		author = "Elastic Security"
		id = "27d409f1-80fd-4d07-815a-4741c48e0bf6"
		fingerprint = "43be41784449fc414c3e3bc7f4ca5827190fa10ac4cdd8500517e2aa6cce2a56"
		creation_date = "2021-09-30"
		last_modified = "2021-10-25"
		description = "Byte sequence based on Metasploit x64 shell_bind_tcp.rb"
		threat_name = "MacOS.Trojan.Metasploit"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x64/shell_bind_tcp.rb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		filetype = "script"

	strings:
		$a1 = { B8 61 00 00 02 6A 02 5F 6A 01 5E 48 31 D2 }

	condition:
		all of them
}
