import "pe"

rule INDICATOR_KB_CERT_2f96a89bfec6e44dd224e8fd7e72d9bb
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f13e4801e13898e839183e3305e1dda7f4c0ebf6eaf7553e18c1ddd4edc94470"
		reason = "Gozi"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NAILS UNLIMITED LIMITED" and pe.signatures[i].serial=="2f:96:a8:9b:fe:c6:e4:4d:d2:24:e8:fd:7e:72:d9:bb")
}
