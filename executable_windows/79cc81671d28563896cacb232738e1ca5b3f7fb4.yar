rule Windows_Trojan_Metasploit_38b8ceec
{
	meta:
		author = "Elastic Security"
		id = "38b8ceec-601c-4117-b7a0-74720e26bf38"
		fingerprint = "44b9022d87c409210b1d0807f5a4337d73f19559941660267d63cd2e4f2ff342"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies the API address lookup function used by metasploit. Also used by other tools (like beacon)."
		threat_name = "Windows.Trojan.Metasploit"
		severity = 85
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = { 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 }

	condition:
		$a1
}
