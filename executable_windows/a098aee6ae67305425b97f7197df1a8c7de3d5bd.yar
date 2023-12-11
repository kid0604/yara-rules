import "pe"

rule INDICATOR_KB_CERT_00ea720222d92dc8d48e3b3c3b0fc360a6
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "522d0f1ca87ef784994dfd63cb0919722dfdb79f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "CAVANAGH NETS LIMITED" and pe.signatures[i].serial=="00:ea:72:02:22:d9:2d:c8:d4:8e:3b:3c:3b:0f:c3:60:a6")
}
