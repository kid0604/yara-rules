import "pe"

rule INDICATOR_KB_CERT_239ba103c2943d2dff5e3211d6800d09
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d8ea0533af5c180ce1f4d6bc377b736208b3efbb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Bcafaecbecacbca" and pe.signatures[i].serial=="23:9b:a1:03:c2:94:3d:2d:ff:5e:32:11:d6:80:0d:09")
}
