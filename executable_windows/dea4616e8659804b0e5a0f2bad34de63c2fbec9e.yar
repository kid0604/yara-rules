import "pe"

rule INDICATOR_KB_CERT_1249aa2ada4967969b71ce63bf187c38
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "c139076033e8391c85ba05508c4017736a8a7d9c1350e6b5996dd94b374f403c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Umbrella LLC" and pe.signatures[i].serial=="12:49:aa:2a:da:49:67:96:9b:71:ce:63:bf:18:7c:38")
}
