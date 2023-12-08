import "pe"

rule INDICATOR_KB_CERT_bce1d49ff444d032ba3dda6394a311e9
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "e9a9ef5dfca4d2e720e86443c6d491175f0e329ab109141e6e2ee4f0e33f2e38"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DECIPHER MEDIA LLC" and pe.signatures[i].serial=="bc:e1:d4:9f:f4:44:d0:32:ba:3d:da:63:94:a3:11:e9")
}
