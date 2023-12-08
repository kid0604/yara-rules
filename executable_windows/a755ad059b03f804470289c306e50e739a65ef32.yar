import "pe"

rule malware_apt15_bs2005
{
	meta:
		author = "Ahmed Zaki"
		md5 = "ed21ce2beee56f0a0b1c5a62a80c128b"
		description = "APT15 bs2005"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "%s&%s&%s&%s" wide ascii
		$ = "%s\\%s" wide ascii
		$ = "WarOnPostRedirect" wide ascii fullword
		$ = "WarnonZoneCrossing" wide ascii fullword
		$ = "^^^^^" wide ascii fullword
		$ = /"?%s\s*"?\s*\/C\s*"?%s\s*>\s*\\?"?%s\\(\w+\.\w+)?"\s*2>&1\s*"?/
		$ = "IEharden" wide ascii fullword
		$ = "DEPOff" wide ascii fullword
		$ = "ShownVerifyBalloon" wide ascii fullword
		$ = "IEHardenIENoWarn" wide ascii fullword

	condition:
		( uint16(0)==0x5A4D and 5 of them ) or ( uint16(0)==0x5A4D and 3 of them and (pe.imports("advapi32.dll","CryptDecrypt") and pe.imports("advapi32.dll","CryptEncrypt") and pe.imports("ole32.dll","CoCreateInstance")))
}
