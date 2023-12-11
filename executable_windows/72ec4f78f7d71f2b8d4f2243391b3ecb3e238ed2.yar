import "pe"

rule INDICATOR_KB_CERT_4026d6291f1ac7cf86c2c81172cfb200
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "2ae4328db08bac015d8965e325b0263c0809d93e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "MztxUCVYqnxgsyqVryViRnMfHFYBgyVMXkXuVGqmyPx" and pe.signatures[i].serial=="40:26:d6:29:1f:1a:c7:cf:86:c2:c8:11:72:cf:b2:00")
}
