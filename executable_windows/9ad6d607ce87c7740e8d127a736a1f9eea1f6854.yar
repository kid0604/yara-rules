import "pe"

rule INDICATOR_KB_CERT_67936a84bed66ef021dbe771de331772
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "8fff75906628b764e99a7a028112a8ec7794097e564f0f897c24c2baaa82ded8"
		reason = "IcedID"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "APEX SOFTWARE DESIGN, LLC" and pe.signatures[i].serial=="67:93:6a:84:be:d6:6e:f0:21:db:e7:71:de:33:17:72")
}
