import "pe"

rule malware_apt15_exchange_tool_alt_1
{
	meta:
		author = "Ahmed Zaki"
		md5 = "d21a7e349e796064ce10f2f6ede31c71"
		description = "This is a an exchange enumeration/hijacking tool used by an APT 15"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "subjectname" fullword
		$s2 = "sendername" fullword
		$s3 = "WebCredentials" fullword
		$s4 = "ExchangeVersion" fullword
		$s5 = "ExchangeCredentials" fullword
		$s6 = "slfilename" fullword
		$s7 = "EnumMail" fullword
		$s8 = "EnumFolder" fullword
		$s9 = "set_Credentials" fullword
		$s10 = "/de" wide
		$s11 = "/sn" wide
		$s12 = "/sbn" wide
		$s13 = "/list" wide
		$s14 = "/enum" wide
		$s15 = "/save" wide
		$s16 = "/ao" wide
		$s17 = "/sl" wide
		$s18 = "/v or /t is null" wide
		$s19 = "2007" wide
		$s20 = "2010" wide
		$s21 = "2010sp1" wide
		$s22 = "2010sp2" wide
		$s23 = "2013" wide
		$s24 = "2013sp1" wide

	condition:
		uint16(0)==0x5A4D and 15 of ($s*)
}
