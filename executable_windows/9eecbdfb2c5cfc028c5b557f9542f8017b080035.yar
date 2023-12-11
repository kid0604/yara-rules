import "pe"

rule INDICATOR_KB_CERT_45d76c63929c4620ab706772f5907f82
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificate"
		thumbprint = "67c4afae16e5e2f98fe26b4597365b3cfed68b58"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "NEON CRAYON LIMITED" and pe.signatures[i].serial=="45:d7:6c:63:92:9c:46:20:ab:70:67:72:f5:90:7f:82")
}
