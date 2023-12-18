import "pe"

rule INDICATOR_KB_CERT_5ef27fc51ee80b30430947c9967db440
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c2dcc4a1ea16e45f86828e81eda20f83e70cbf77e152ddd80b1b4a730ef77551"
		reason = "RedLineStealer"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMCERT,LLC" and pe.signatures[i].serial=="5e:f2:7f:c5:1e:e8:0b:30:43:09:47:c9:96:7d:b4:40")
}
