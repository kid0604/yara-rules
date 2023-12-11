import "pe"

rule INDICATOR_KB_CERT_38989ec61ecdb7391ff5647f7d58ad18
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "71e74a735c72d220aa45e9f1b83f0b867f2da166"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RotA Games ApS" and pe.signatures[i].serial=="38:98:9e:c6:1e:cd:b7:39:1f:f5:64:7f:7d:58:ad:18")
}
