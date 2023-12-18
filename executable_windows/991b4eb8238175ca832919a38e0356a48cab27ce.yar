import "pe"

rule INDICATOR_KB_CERT_06675181e7b5e1030b3d40926e2a47d3
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b617253b3695fd498d645bd8278d1bdae2bc36bd4da713c6938e3fe6b0cdb9a4"
		reason = "NetWire"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ORANGE VIEW LIMITED" and pe.signatures[i].serial=="06:67:51:81:e7:b5:e1:03:0b:3d:40:92:6e:2a:47:d3")
}
