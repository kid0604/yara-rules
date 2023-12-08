rule Windows_Trojan_IcedID_1cd868a6
{
	meta:
		author = "Elastic Security"
		id = "1cd868a6-d2ec-4c48-a69a-aaa6c7af876c"
		fingerprint = "3e76b3ac03c5268923cfd5d0938745d66cda273d436b83bee860250fdcca6327"
		creation_date = "2021-02-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.IcedID"
		reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
		reference_sample = "68dce9f214e7691db77a2f03af16a669a3cb655699f31a6c1f5aaede041468ff"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan IcedID variant"
		filetype = "executable"

	strings:
		$a = { 24 2C B9 09 00 00 00 2A C2 2C 07 88 44 24 0F 0F B6 C3 6B C0 43 89 44 }

	condition:
		all of them
}
