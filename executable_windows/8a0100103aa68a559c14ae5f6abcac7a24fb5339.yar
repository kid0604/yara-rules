import "pe"

rule INDICATOR_KB_CERT_13c7b92282aae782bfb00baf879935f4
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c253cce2094c0a4ec403518d4fbf18c650e5434759bc690758cb3658b75c8baa"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "THE WIZARD GIFT CORPORATION" and pe.signatures[i].serial=="13:c7:b9:22:82:aa:e7:82:bf:b0:0b:af:87:99:35:f4")
}
