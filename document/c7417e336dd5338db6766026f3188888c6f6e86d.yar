rule SUSP_Doc_RTF_ExternalResource_May22
{
	meta:
		description = "Detects a suspicious pattern in RTF files which downloads external resources as seen in CVE-2022-30190 / Follina exploitation"
		author = "Tobias Michalski, Christian Burkard"
		date = "2022-05-30"
		modified = "2022-05-31"
		reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
		score = 70
		os = "windows"
		filetype = "document"

	strings:
		$s1 = " LINK htmlfile \"http" ascii
		$s2 = ".html!\" " ascii

	condition:
		uint32be(0)==0x7B5C7274 and filesize <300KB and all of them
}
