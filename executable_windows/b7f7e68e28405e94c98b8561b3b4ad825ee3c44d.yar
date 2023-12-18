import "pe"

rule INDICATOR_KB_CERT_984e84cfe362e278f558e2c70aaafac2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0b2d1dad72c69644f80ad871743878b5eb1e45e451d0d2c9579bdf81384f8727"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Arctic Nights Äkäslompolo Oy" and pe.signatures[i].serial=="98:4e:84:cf:e3:62:e2:78:f5:58:e2:c7:0a:aa:fa:c2")
}
