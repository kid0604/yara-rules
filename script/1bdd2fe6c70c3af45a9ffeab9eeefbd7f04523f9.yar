rule MacOS_Trojan_Metasploit_c7b7a90b
{
	meta:
		author = "Elastic Security"
		id = "c7b7a90b-aaf2-482d-bb95-dee20a75379e"
		fingerprint = "c4b2711417f5616ca462149882a7f33ce53dd1b8947be62fe0b818c51e4f4b2f"
		creation_date = "2021-09-30"
		last_modified = "2021-10-25"
		description = "Byte sequence based on Metasploit stager reverse_tcp.rb"
		threat_name = "MacOS.Trojan.Metasploit"
		reference = "https://github.com/rapid7/metasploit-framework/blob/master/modules/payloads/stagers/osx/x86/reverse_tcp.rb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		filetype = "script"

	strings:
		$a1 = { 31 C0 99 50 40 50 40 50 52 B0 61 CD 80 72 }

	condition:
		all of them
}
