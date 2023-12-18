import "pe"

rule INDICATOR_KB_CERT_da20761afbb0463c55b1ea88bbc7ec57
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f12dd6e77ffab75870b24dd5bfda5a360843f9e5591e764be9f0a2ac59a710d3"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CLEVER CLOSE s.r.o." and pe.signatures[i].serial=="da:20:76:1a:fb:b0:46:3c:55:b1:ea:88:bb:c7:ec:57")
}
