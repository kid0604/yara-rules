import "pe"

rule INDICATOR_KB_CERT_1e508bb2398808bc420a5a1f67ba5d0b
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "63a3ca4114aef8d5076ec84ff78d2319d5305e5b"
		hash1 = "7ff82a6621e0dd7c29c2e6bcd63920f9b58bc254df9479618b912a1e788ff18b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "WakeNet AB" and pe.signatures[i].serial=="1e:50:8b:b2:39:88:08:bc:42:0a:5a:1f:67:ba:5d:0b")
}
