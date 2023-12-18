import "pe"

rule INDICATOR_KB_CERT_101d6a5a29d9a77807553ceac669d853
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "cd6aa9a7a4898e42b8361dc3542d0afb72e6deefc0b85ebfb55d282a2982b994"
		reason = "IcedID"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BIC GROUP LIMITED" and pe.signatures[i].serial=="10:1d:6a:5a:29:d9:a7:78:07:55:3c:ea:c6:69:d8:53")
}
