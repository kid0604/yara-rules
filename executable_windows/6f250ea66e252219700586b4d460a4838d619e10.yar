import "pe"

rule INDICATOR_KB_CERT_709d547a2f09d39c4c2334983f2cbf50
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "f10095c5e36e6bce0759f52dd11137756adc3b53"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BMUZVYUGWSQWLAIISX" and pe.signatures[i].serial=="70:9d:54:7a:2f:09:d3:9c:4c:23:34:98:3f:2c:bf:50")
}
