import "pe"

rule INDICATOR_KB_CERT_c51f4cf4d82bc920421e1ad93e39d490
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d17dc7ef018e13b9a482b60871e25447fb1ae724dfe69b5287dce6b9b78d84a9"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CUT AHEAD LTD" and pe.signatures[i].serial=="c5:1f:4c:f4:d8:2b:c9:20:42:1e:1a:d9:3e:39:d4:90")
}
