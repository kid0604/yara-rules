import "pe"

rule INDICATOR_KB_CERT_4a2e337fff23e5b2a1321ffde56d1759
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "67099e0c41c102535d388fab1de576433f2ded2b08fb7da1bf66e3bdaba4eeb4"
		reason = "IcedID"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Karolina Klimowska" and pe.signatures[i].serial=="4a:2e:33:7f:ff:23:e5:b2:a1:32:1f:fd:e5:6d:17:59")
}
