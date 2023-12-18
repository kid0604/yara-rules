import "pe"

rule INDICATOR_KB_CERT_6daa67498c3a5d8133f28fefe9ccc20e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f54146fadad277f67b14cfebd13cbada9789281cee7165db0277ad51621adb97"
		reason = "ParallaxRAT"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rimsara Development OU" and pe.signatures[i].serial=="6d:aa:67:49:8c:3a:5d:81:33:f2:8f:ef:e9:cc:c2:0e")
}
