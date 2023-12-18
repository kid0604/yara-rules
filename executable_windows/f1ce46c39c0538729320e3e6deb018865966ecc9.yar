import "pe"

rule INDICATOR_KB_CERT_0c48732873ac8ccebaf8f0e1e8329cec
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "14ffc96c8cc2ea2d732ed75c3093d20187a4c72d02654ff4520448ba7f8c7df6"
		reason = "HermeticWiper"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Hermetica Digital Ltd" and pe.signatures[i].serial=="0c:48:73:28:73:ac:8c:ce:ba:f8:f0:e1:e8:32:9c:ec")
}
