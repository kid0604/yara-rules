import "pe"

rule INDICATOR_KB_CERT_0139dde119bb320dfb9f5defe3f71245
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "23d13a8e48a6eff191a5d6a0635b99467c2e7242ae520479cae130fbd41cc645"
		reason = "RedLineStealer"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Hangil IT Co., Ltd" and pe.signatures[i].serial=="01:39:dd:e1:19:bb:32:0d:fb:9f:5d:ef:e3:f7:12:45")
}
