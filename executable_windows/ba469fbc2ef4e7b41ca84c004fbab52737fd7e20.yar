import "pe"

rule INDICATOR_KB_CERT_00d875b3e3f2db6c3eb426e24946066111
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d27211a59dc8a4b3073d116621b6857c3d70ed04"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Kubit LLC" and pe.signatures[i].serial=="00:d8:75:b3:e3:f2:db:6c:3e:b4:26:e2:49:46:06:61:11")
}
