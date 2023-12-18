import "pe"

rule INDICATOR_KB_CERT_5c9f5f96726a6e6fc3b8bb153ac82af2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "285925b7c7c692f8d71d980dcf2ddb4c208a0f7b826ead34db402755d1a0f6de"
		reason = "IcedID"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "1105 SOFTWARE LLC" and pe.signatures[i].serial=="5c:9f:5f:96:72:6a:6e:6f:c3:b8:bb:15:3a:c8:2a:f2")
}
