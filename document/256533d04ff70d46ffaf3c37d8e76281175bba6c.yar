rule SUSP_DOC_RTF_ExternalResource_EMAIL_Jun22
{
	meta:
		description = "Detects a suspicious pattern in RTF files which downloads external resources as seen in CVE-2022-30190 / Follina exploitation inside e-mail attachment"
		author = "Christian Burkard"
		date = "2022-06-01"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		score = 70
		os = "windows,linux,macos"
		filetype = "document"

	strings:
		$sa1 = "PFJlbGF0aW9uc2hpcH" ascii
		$sa2 = "xSZWxhdGlvbnNoaXBz" ascii
		$sa3 = "8UmVsYXRpb25zaGlwc" ascii
		$sb1 = "VGFyZ2V0TW9kZT0iRXh0ZXJuYWwi" ascii
		$sb2 = "RhcmdldE1vZGU9IkV4dGVybmFsI" ascii
		$sb3 = "UYXJnZXRNb2RlPSJFeHRlcm5hbC" ascii
		$sc1 = "Lmh0bWwhI" ascii
		$sc2 = "5odG1sIS" ascii
		$sc3 = "uaHRtbCEi" ascii

	condition:
		filesize <400KB and 1 of ($sa*) and 1 of ($sb*) and 1 of ($sc*)
}
