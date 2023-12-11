rule MacOS_Trojan_Metasploit_2992b917
{
	meta:
		author = "Elastic Security"
		id = "2992b917-32bd-4fd8-8221-0d061239673d"
		fingerprint = "055129bc7931d0334928be00134c109ab36825997b2877958e0ca9006b55575e"
		creation_date = "2021-09-30"
		last_modified = "2021-10-25"
		description = "Byte sequence based on Metasploit vforkshell_reverse_tcp.rb"
		threat_name = "MacOS.Trojan.Metasploit"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/singles/osx/x86/vforkshell_reverse_tcp.rb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		filetype = "script"

	strings:
		$a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 72 6D 89 C7 52 52 68 7F 00 00 01 68 00 02 34 12 89 E3 6A }

	condition:
		all of them
}
