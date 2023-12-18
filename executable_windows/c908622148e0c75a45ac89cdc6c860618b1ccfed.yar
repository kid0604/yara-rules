import "pe"

rule INDICATOR_KB_CERT_40f5660a90301e7a8a8c3b42
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "2ac041e3c46c82fbcee34617ee31336e845e18efe6b9ae5c8811351db5b56da2"
		reason = "Cobalt Strike"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Booz Allen Hamilton Inc." and pe.signatures[i].serial=="40:f5:66:0a:90:30:1e:7a:8a:8c:3b:42")
}
