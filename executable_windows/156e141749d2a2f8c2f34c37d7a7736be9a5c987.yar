import "pe"

rule INDICATOR_KB_CERT_0c14b611a44a1bae0e8c7581651845b6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "c3288c7fbb01214c8f2dc3172c3f5c48f300cb8b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NEEDCODE SP Z O O" and pe.signatures[i].serial=="0c:14:b6:11:a4:4a:1b:ae:0e:8c:75:81:65:18:45:b6")
}
