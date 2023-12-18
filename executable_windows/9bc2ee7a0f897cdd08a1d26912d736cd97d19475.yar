import "pe"

rule INDICATOR_KB_CERT_651f3e5b491b197d20c49b9c7b25b775
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0ee11d5917c486b7a57b7c3c566acec251170e98a577164f36b7d7d34f035499"
		reason = "NetSupport"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rhynedahll Software LLC" and pe.signatures[i].serial=="65:1f:3e:5b:49:1b:19:7d:20:c4:9b:9c:7b:25:b7:75")
}
