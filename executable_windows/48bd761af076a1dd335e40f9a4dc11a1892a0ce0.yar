import "pe"

rule INDICATOR_KB_CERT_f6ad45188e5566aa317be23b4b8b2c2f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ae7db8b64e8abd9d36876f049b9770d90c0868d7fe1a2d37cf327df69fa2dbfe"
		reason = "Numando"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Gary Kramlich" and pe.signatures[i].serial=="f6:ad:45:18:8e:55:66:aa:31:7b:e2:3b:4b:8b:2c:2f")
}
