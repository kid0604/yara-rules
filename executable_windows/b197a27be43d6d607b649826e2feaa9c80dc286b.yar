import "pe"

rule INDICATOR_KB_CERT_00aa12c95d2bcde0ce141c6f1145b0d7ef
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "1383c4aa2900882f9892696c537e83f1fb20a43f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "PROKON, OOO" and pe.signatures[i].serial=="00:aa:12:c9:5d:2b:cd:e0:ce:14:1c:6f:11:45:b0:d7:ef")
}
