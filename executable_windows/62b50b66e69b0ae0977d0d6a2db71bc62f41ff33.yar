import "pe"

rule INDICATOR_KB_CERT_00d1737e5a94d2aff121163df177ed7cf7
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "ed2e4f72e8cb9b008a28b31de440f024381e4c8d"
		hash1 = "66dfb7c408d734edc2967d50244babae27e4268ea93aa0daa5e6bbace607024c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BedstSammen ApS" and (pe.signatures[i].serial=="d1:73:7e:5a:94:d2:af:f1:21:16:3d:f1:77:ed:7c:f7" or pe.signatures[i].serial=="00:d1:73:7e:5a:94:d2:af:f1:21:16:3d:f1:77:ed:7c:f7"))
}
