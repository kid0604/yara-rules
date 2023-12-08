import "pe"

rule INDICATOR_KB_CERT_00d338f8a490e37e6c2be80a0e349929fa
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "480a9ce15fc76e03f096fda5af16e44e0d6a212d6f09a898f51ad5206149bbe1"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SAGUARO ApS" and pe.signatures[i].serial=="00:d3:38:f8:a4:90:e3:7e:6c:2b:e8:0a:0e:34:99:29:fa")
}
