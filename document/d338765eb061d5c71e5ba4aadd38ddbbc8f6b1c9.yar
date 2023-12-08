rule INDICATOR_RTF_Equation_PowerShell_Downloader
{
	meta:
		description = "Detects RTF documents that references both Microsoft Equation Editor and PowerShell. Common exploit + dropper behavior."
		author = "ditekSHen"
		snort2_sid = "910004-910005"
		snort3_sid = "910002"
		clamav_sig = "INDICATOR.RTF.EquationPowerShellDownloader"
		os = "windows"
		filetype = "document"

	strings:
		$eq = "0200000002CE020000000000C000000000000046" ascii nocase
		$ps = "706f7765727368656c6c" ascii nocase
		$obj1 = "\\objhtml" ascii
		$obj2 = "\\objdata" ascii
		$obj3 = "\\objupdate" ascii
		$obj4 = "\\objemb" ascii
		$obj5 = "\\objautlink" ascii
		$obj6 = "\\objlink" ascii
		$obj7 = "\\mmath" ascii

	condition:
		uint32(0)==0x74725c7b and (($ps and $eq) and 1 of ($obj*))
}
