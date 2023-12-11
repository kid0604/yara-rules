import "pe"

rule INDICATOR_KB_CERT_3990362c34015ce4c23ecc3377fd3c06
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "48444dec9d6839734d8383b110faabe05e697d45"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "RZOH ApS" and pe.signatures[i].serial=="39:90:36:2c:34:01:5c:e4:c2:3e:cc:33:77:fd:3c:06")
}
