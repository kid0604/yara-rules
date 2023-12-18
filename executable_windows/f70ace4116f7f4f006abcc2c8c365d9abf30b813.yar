import "pe"

rule INDICATOR_KB_CERT_ff52eb011bb748fee75153cbe1e50dd6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c75025c80ab583a6ab87070e5b65c93cb59b48e0cbb5f99113e354a96f8fcd39"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TASK ANNA LIMITED" and pe.signatures[i].serial=="ff:52:eb:01:1b:b7:48:fe:e7:51:53:cb:e1:e5:0d:d6")
}
