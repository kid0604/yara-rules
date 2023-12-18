import "pe"

rule INDICATOR_KB_CERT_7d27332c3cb3a382a4fd232c5c66a2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "935af7361c09f45dcf3fa6e4f4fd176913c47673104272259b40de55566cabed"
		reason = "Silence"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MALVINA RECRUITMENT LIMITED" and pe.signatures[i].serial=="7d:27:33:2c:3c:b3:a3:82:a4:fd:23:2c:5c:66:a2")
}
