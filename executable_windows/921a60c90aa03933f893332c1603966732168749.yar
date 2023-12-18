import "pe"

rule INDICATOR_KB_CERT_a32b8b4f1be43c23eb2848ab4ef06bb2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f7a578c93fd98ade3d259ac47f152d8c9115bc5df7e2f57d107a66db3f833f0f"
		reason = "NetSupport RAT"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Pak El AB" and pe.signatures[i].serial=="a3:2b:8b:4f:1b:e4:3c:23:eb:28:48:ab:4e:f0:6b:b2")
}
