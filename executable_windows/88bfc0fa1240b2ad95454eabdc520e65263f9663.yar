import "pe"

rule INDICATOR_KB_CERT_5b1f9ec88d185631ab032dbfd5166c0d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a46234c01e9f9904e500aefad4b5718d86aaec4e084b3d8ffbfe5724f8ddda45"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TOPFLIGHT GROUP LIMITED" and pe.signatures[i].serial=="5b:1f:9e:c8:8d:18:56:31:ab:03:2d:bf:d5:16:6c:0d")
}
