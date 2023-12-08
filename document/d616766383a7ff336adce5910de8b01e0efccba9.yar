rule INDICATOR_RTF_Equation_BITSAdmin_Downloader
{
	meta:
		description = "Detects RTF documents that references both Microsoft Equation Editor and BITSAdmin. Common exploit + dropper behavior."
		author = "ditekSHen"
		snort2_sid = "910002-910003"
		snort3_sid = "910001"
		clamav_sig = "INDICATOR.RTF.EquationBITSAdminDownloader"
		os = "windows"
		filetype = "document"

	strings:
		$eq = "0200000002CE020000000000C000000000000046" ascii nocase
		$ba = "6269747361646d696e" ascii nocase
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii
		$obj7 = "\\mmath" ascii

	condition:
		uint32(0)==0x74725c7b and (($eq and $ba) and 1 of ($obj*))
}
