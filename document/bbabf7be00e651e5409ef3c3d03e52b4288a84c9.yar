rule SUSP_Excel_IQY_RemoteURI_Syntax
{
	meta:
		description = "Detects files with Excel IQY RemoteURI syntax"
		author = "Nick Carr"
		score = 65
		reference = "https://twitter.com/ItsReallyNick/status/1030330473954897920"
		date = "2018-08-17"
		os = "windows"
		filetype = "document"

	strings:
		$URL = "http"

	condition:
		uint32(0)==0x0d424557 and uint32(4)==0x0a0d310a and filesize <1MB and $URL
}
