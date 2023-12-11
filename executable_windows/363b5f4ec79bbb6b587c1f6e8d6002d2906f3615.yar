rule Windows_Trojan_RedLineStealer_17ee6a17
{
	meta:
		author = "Elastic Security"
		id = "17ee6a17-161e-454a-baf1-2734995c82cd"
		fingerprint = "a1f75937e83f72f61e027a1045374d3bd17cd387b223a6909b9aed52d2bc2580"
		creation_date = "2021-06-12"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "497bc53c1c75003fe4ae3199b0ff656c085f21dffa71d00d7a3a33abce1a3382"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows Trojan RedLineStealer"
		filetype = "executable"

	strings:
		$a1 = "RedLine.Logic.SQLite" ascii fullword
		$a2 = "RedLine.Reburn.Data.Browsers.Gecko" ascii fullword
		$a3 = "RedLine.Client.Models.Gecko" ascii fullword
		$b1 = "SELECT * FROM Win32_Process Where SessionId='{0}'" wide fullword
		$b2 = "get_encryptedUsername" ascii fullword
		$b3 = "https://icanhazip.com" wide fullword
		$b4 = "GetPrivate3Key" ascii fullword
		$b5 = "get_GrabTelegram" ascii fullword
		$b6 = "<GrabUserAgent>k__BackingField" ascii fullword

	condition:
		1 of ($a*) or all of ($b*)
}
