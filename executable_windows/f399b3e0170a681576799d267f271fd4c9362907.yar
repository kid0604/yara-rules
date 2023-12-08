import "pe"

rule INDICATOR_KB_CERT_00e04a344b397f752a45b128a594a3d6b5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "d73229f3b7c2025a5a56e6e189be8a9120f1b3b0d8a78b7f62eff5c8d2293330"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Highweb Ireland Operations Limited" and pe.signatures[i].serial=="00:e0:4a:34:4b:39:7f:75:2a:45:b1:28:a5:94:a3:d6:b5")
}
