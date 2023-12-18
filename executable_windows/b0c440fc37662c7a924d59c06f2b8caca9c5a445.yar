import "pe"

rule INDICATOR_KB_CERT_626735ed30e50e3e0553986d806bfc54
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a1488004ec967faf6c66f55440bbde0de47065490f7c758f3ca1315bb0ef3b97"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FISH ACCOUNTING & TRANSLATING LIMITED" and pe.signatures[i].serial=="62:67:35:ed:30:e5:0e:3e:05:53:98:6d:80:6b:fc:54")
}
