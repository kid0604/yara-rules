import "pe"

rule INDICATOR_KB_CERT_d3aee8abb9948844a3ac1c04cc7e6bdf
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e386450257e170981513b7001a82fb029f0931e5c2f11c6d9b86660da0b89a66"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HOUSE 9A s.r.o" and pe.signatures[i].serial=="d3:ae:e8:ab:b9:94:88:44:a3:ac:1c:04:cc:7e:6b:df")
}
