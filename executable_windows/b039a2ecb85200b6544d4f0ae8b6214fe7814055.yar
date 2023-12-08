import "pe"

rule INDICATOR_KB_CERT_dde89c647dc2138244228040e324dc77
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1d9aaa1bc7d6fc5a76295dd1cf692fe4a1283f04"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "WMade by H5et.com" and pe.signatures[i].serial=="dd:e8:9c:64:7d:c2:13:82:44:22:80:40:e3:24:dc:77")
}
