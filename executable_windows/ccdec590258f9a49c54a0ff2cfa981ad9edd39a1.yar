import "pe"

rule INDICATOR_KB_CERT_0cf2d0b5bfdd68cf777a0c12f806a569
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0c212cdf3d9a46621c19af5c494ff6bad25d3190"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PROTIP d.o.o." and pe.signatures[i].serial=="0c:f2:d0:b5:bf:dd:68:cf:77:7a:0c:12:f8:06:a5:69")
}
