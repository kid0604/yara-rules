rule Windows_Trojan_Generic_c7fd8d38
{
	meta:
		author = "Elastic Security"
		id = "c7fd8d38-eaba-424d-b91a-098c439dab6b"
		fingerprint = "dc14cd519b3bbad7c2e655180a584db0a4e2ad4eea073a52c94b0a88152b37ba"
		creation_date = "2022-02-17"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Generic"
		reference_sample = "a1702ec12c2bf4a52e11fbdab6156358084ad2c662c8b3691918ef7eabacde96"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Generic"
		filetype = "executable"

	strings:
		$a1 = "PCREDENTIAL" ascii fullword
		$a2 = "gHotkey" ascii fullword
		$a3 = "EFORMATEX" ascii fullword
		$a4 = "ZLibEx" ascii fullword
		$a5 = "9Root!" ascii fullword

	condition:
		all of them
}
