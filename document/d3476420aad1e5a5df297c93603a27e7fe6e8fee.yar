rule INDICATOR_RTF_Equation_CertUtil_Downloader
{
	meta:
		description = "Detects RTF documents that references both Microsoft Equation Editor and CertUtil. Common exploit + dropper behavior."
		author = "ditekSHen"
		snort2_sid = "910006-910007"
		snort3_sid = "910003"
		clamav_sig = "INDICATOR.RTF.EquationCertUtilDownloader"
		os = "windows"
		filetype = "document"

	strings:
		$eq = "0200000002CE020000000000C000000000000046" ascii nocase
		$cu = "636572747574696c" ascii nocase
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii
		$obj7 = "\\mmath" ascii

	condition:
		uint32(0)==0x74725c7b and (($eq and $cu) and 1 of ($obj*))
}
