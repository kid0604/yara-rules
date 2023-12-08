rule Windows_Trojan_Metasploit_c9773203
{
	meta:
		author = "Elastic Security"
		id = "c9773203-6d1e-4246-a1e0-314217e0207a"
		fingerprint = "afde93eeb14b4d0c182f475a22430f101394938868741ffa06445e478b6ece36"
		creation_date = "2021-04-07"
		last_modified = "2021-08-23"
		description = "Identifies the 64 bit API hashing function used by Metasploit. This has been re-used by many other malware families."
		threat_name = "Windows.Trojan.Metasploit"
		reference = "https://github.com/rapid7/metasploit-framework/blob/04e8752b9b74cbaad7cb0ea6129c90e3172580a2/external/source/shellcode/windows/x64/src/block/block_api.asm"
		severity = 10
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a = { 48 31 C0 AC 41 C1 C9 0D 41 01 C1 38 E0 75 F1 4C 03 4C 24 08 45 39 D1 }

	condition:
		all of them
}
