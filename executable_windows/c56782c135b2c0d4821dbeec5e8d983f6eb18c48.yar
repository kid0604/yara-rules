import "pe"

rule INDICATOR_KB_CERT_c81319d20c6f1f1aec3398522189d90c
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "18d8be8afa6613e2ef037598a6e08e0ef197d420f21aa4050f473fcabd16644a"
		reason = "RedLineStealer"
		reference = "https://bazaar.abuse.ch/faq/#cscb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "AMCERT,LLC" and pe.signatures[i].serial=="c8:13:19:d2:0c:6f:1f:1a:ec:33:98:52:21:89:d9:0c")
}
