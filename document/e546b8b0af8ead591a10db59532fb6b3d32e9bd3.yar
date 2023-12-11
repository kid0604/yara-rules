rule INDICATOR_OLE_Suspicious_Reverse
{
	meta:
		description = "detects OLE documents containing VB scripts with reversed suspicious strings"
		author = "ditekSHen"
		os = "windows"
		filetype = "document"

	strings:
		$vb = "\\VBE7.DLL" ascii
		$cmd1 = "CMD C:\\" nocase ascii
		$cmd2 = "CMD /c " nocase ascii
		$kw1 = "]rAHC[" nocase ascii
		$kw2 = "ekOVNI" nocase ascii
		$kw3 = "EcaLPEr" nocase ascii
		$kw4 = "TcEJBO-WEn" nocase ascii
		$kw5 = "eLbAirav-Teg" nocase ascii
		$kw6 = "ReveRSE(" nocase ascii
		$kw7 = "-JOIn" nocase ascii

	condition:
		uint16(0)==0xcfd0 and $vb and ((1 of ($cmd*) and 1 of ($kw*)) or (2 of ($kw*)))
}
