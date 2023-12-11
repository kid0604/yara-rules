import "pe"

rule INDICATOR_KB_CERT_084b6f19898214a02a5f32e6ea69f0fd
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4b89f40ba2c83c3e65d2be59abb3385cde401581"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "TORG-ALYANS, LLC" and pe.signatures[i].serial=="08:4b:6f:19:89:82:14:a0:2a:5f:32:e6:ea:69:f0:fd")
}
