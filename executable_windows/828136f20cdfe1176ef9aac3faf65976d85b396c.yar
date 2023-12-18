import "pe"

rule INDICATOR_KB_CERT_3ab74a2ebf93447adb83554b5564fe03
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8ed289fcc40bbc150a52b733123f6094ccfb2c499d6e932b0d9a6001490fb7e6"
		reason = "RedLineStealer"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "IMPERIOUS TECHNOLOGIES LIMITED" and pe.signatures[i].serial=="3a:b7:4a:2e:bf:93:44:7a:db:83:55:4b:55:64:fe:03")
}
