import "pe"

rule INDICATOR_KB_CERT_332bd5801e8415585e72c87e0e2ec71d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "47338c1a0ea425c47dede188d10ca95288514f369fe8a5105752bd8d906b8cbc"
		reason = "NetSupport"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Elite Marketing Strategies, Inc." and pe.signatures[i].serial=="33:2b:d5:80:1e:84:15:58:5e:72:c8:7e:0e:2e:c7:1d")
}
