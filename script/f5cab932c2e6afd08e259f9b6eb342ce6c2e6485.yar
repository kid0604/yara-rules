rule MacOS_Trojan_Metasploit_4bd6aaca
{
	meta:
		author = "Elastic Security"
		id = "4bd6aaca-f519-4d20-b3af-d376e0322a7e"
		fingerprint = "f4957b565d2b86c79281a0d3b2515b9a0c72f9c9c7b03dae18a3619d7e2fc3dc"
		creation_date = "2021-09-30"
		last_modified = "2021-10-25"
		description = "Byte sequence based on Metasploit stager x86 bind_tcp.rb"
		threat_name = "MacOS.Trojan.Metasploit"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/osx/x86/bind_tcp.rb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		filetype = "script"

	strings:
		$a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 0F 82 7D }

	condition:
		all of them
}
