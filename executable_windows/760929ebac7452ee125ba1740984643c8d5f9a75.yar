import "pe"

rule INDICATOR_KB_CERT_06808c5934da036a1297a936d72e93d4
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "efb70718bc00393a01694f255a28e30e9d2142a4"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Rhaon Entertainment Inc" and pe.signatures[i].serial=="06:80:8c:59:34:da:03:6a:12:97:a9:36:d7:2e:93:d4")
}
