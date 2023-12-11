import "pe"

rule INDICATOR_KB_CERT_4af27cd14f5c809eec1f46e483f03898
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "5fa9a98f003f2680718cbe3a7a3d57d7ba347ecb"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DAhan Advertising planning" and pe.signatures[i].serial=="4a:f2:7c:d1:4f:5c:80:9e:ec:1f:46:e4:83:f0:38:98")
}
