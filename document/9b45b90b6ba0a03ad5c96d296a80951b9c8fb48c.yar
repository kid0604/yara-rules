rule INDICATOR_RTF_Ancalog_Exploit_Builder_Document
{
	meta:
		description = "Detects documents generated by Phantom Crypter/Ancalog"
		author = "ditekSHen"
		snort2_sid = "910000-910001"
		snort3_sid = "910000"
		clamav_sig = "INDICATOR.RTF.AncalogExploitBuilderDocument"
		os = "windows"
		filetype = "document"

	strings:
		$builder1 = "{\\*\\ancalog" ascii
		$builder2 = "\\ancalog" ascii

	condition:
		uint32(0)==0x74725c7b and 1 of ($builder*)
}
