import "pe"

rule INDICATOR_KB_CERT_0a392f03ded5d73cdeeda75052a57176
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "cf1d95b39cc695e90dc2ca8b1b50f33b71f9f21091df2b72ed97f0759b5ddde4"
		reason = "Quakbot"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "FLOWER COMPUTERS LTD" and pe.signatures[i].serial=="0a:39:2f:03:de:d5:d7:3c:de:ed:a7:50:52:a5:71:76")
}
