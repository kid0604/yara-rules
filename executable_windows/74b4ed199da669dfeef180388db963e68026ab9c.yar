import "pe"

rule INDICATOR_KB_CERT_0ca1d9391cf5fe3e696831d98d6c35a6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "0689776ca5ca0ca9641329dc29efdb61302d7378"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "www.norton.com" and pe.signatures[i].serial=="0c:a1:d9:39:1c:f5:fe:3e:69:68:31:d9:8d:6c:35:a6")
}
