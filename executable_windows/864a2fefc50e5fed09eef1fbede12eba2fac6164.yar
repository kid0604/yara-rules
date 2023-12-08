import "pe"

rule malware_apt15_exchange_tool
{
	meta:
		author = "Ahmed Zaki"
		md5 = "d21a7e349e796064ce10f2f6ede31c71"
		description = "This is a an exchange enumeration/hijacking tool used by an APT 15"
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
		$s18 = "/v or /t is null" wide
		$s24 = "2013sp1" wide

	condition:
		uint16(0)==0x5A4D and all of them
}
