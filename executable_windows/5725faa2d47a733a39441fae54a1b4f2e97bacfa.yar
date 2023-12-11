import "pe"

rule INDICATOR_KB_CERT_00f13a4f94bf233525
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "974eb056bb7467d54aae25a908ce661dac59c786"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SocketOptionName" and (pe.signatures[i].serial=="f1:3a:4f:94:bf:23:35:25" or pe.signatures[i].serial=="00:f1:3a:4f:94:bf:23:35:25"))
}
