import "pe"

rule INDICATOR_KB_CERT_4679c5398a279318365fd77a84445699
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8fcef52c16987307f4e1f7d4b62304c65aedb952c90bb2ead8321f1e1d7c9a6e"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HURT GROUP HOLDINGS LIMITED" and pe.signatures[i].serial=="46:79:c5:39:8a:27:93:18:36:5f:d7:7a:84:44:56:99")
}
