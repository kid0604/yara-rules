import "pe"

rule INDICATOR_KB_CERT_00c04f5d17af872cb2c37e3367fe761d0d
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "7f52ece50576fcc7d66e028ecec89d3faedeeedb953935e215aac4215c9f4d63"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DES SP Z O O" and (pe.signatures[i].serial=="00:c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d" or pe.signatures[i].serial=="c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d"))
}
