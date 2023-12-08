rule INDICATOR_TOOL_ExchangeExploit
{
	meta:
		author = "ditekSHen"
		description = "Hunt for executables potentially embedding Exchange Server exploitation artificats"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "ecp/default.flt?" ascii wide nocase
		$s2 = "owa/auth/logon.aspx?" ascii wide nocase
		$s3 = "X-AnonResource-Backend" ascii wide
		$s4 = "EWS/Exchange.asmx?" ascii wide nocase
		$s5 = "X-BEResource" ascii wide
		$s6 = "https://%s/owa/auth/" ascii wide

	condition:
		( uint16(0)==0x5a4d or uint16(0)==0x457f) and 5 of them
}
