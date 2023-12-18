import "pe"

rule INDICATOR_KB_CERT_15c21dab7f4e644e4b35c4858004d8a9
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "34a9cd401a5a86c5194954df3a497094c01b6603264aab5cf7d9b3c4a0074801"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "P.REGO, s.r.o." and pe.signatures[i].serial=="15:c2:1d:ab:7f:4e:64:4e:4b:35:c4:85:80:04:d8:a9")
}
