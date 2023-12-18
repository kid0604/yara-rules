rule SUSP_Excel_IQY_RemoteURI_Syntax_alt_1
{
	meta:
		description = "Detects files with Excel IQY RemoteURI syntax"
		author = "Nick Carr"
		reference = "https://twitter.com/ItsReallyNick/status/1030330473954897920"
		date = "2018-08-17"
		modified = "2023-11-25"
		score = 55
		id = "ea3427da-9cce-5ad9-9c78-e3cee802ba80"
		os = "windows"
		filetype = "document"

	strings:
		$URL = "http"
		$fp1 = "https://go.microsoft.com"

	condition:
		uint32(0)==0x0d424557 and uint32(4)==0x0a0d310a and filesize <1MB and $URL and not 1 of ($fp*)
}
