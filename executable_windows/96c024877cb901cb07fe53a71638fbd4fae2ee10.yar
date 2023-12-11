import "pe"

rule INDICATOR_KB_CERT_00f0031491b673ecdf533d4ebe4b54697f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "01e201cce1024237978baccf5b124261aa5edb01"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Eebbffbceacddbfaeefaecdbaf" and pe.signatures[i].serial=="00:f0:03:14:91:b6:73:ec:df:53:3d:4e:be:4b:54:69:7f")
}
