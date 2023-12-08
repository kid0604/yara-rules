rule Windows_Ransomware_Bitpaymer_d74273b3 : beta
{
	meta:
		author = "Elastic Security"
		id = "d74273b3-d109-4b5d-beff-dffee9a984b1"
		fingerprint = "4f913f06f7c7decbeb78187c566674f91ebbf929ad7057641659bb756cf2991b"
		creation_date = "2020-06-25"
		last_modified = "2021-08-23"
		description = "Identifies BITPAYMER ransomware"
		threat_name = "Windows.Ransomware.Bitpaymer"
		reference = "https://www.welivesecurity.com/2018/01/26/friedex-bitpaymer-ransomware-work-dridex-authors/"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$b1 = { 24 E8 00 00 00 29 F0 19 F9 89 8C 24 88 00 00 00 89 84 24 84 00 }

	condition:
		1 of ($b*)
}
