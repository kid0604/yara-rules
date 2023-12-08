import "pe"

rule INDICATOR_KB_CERT_029685cda1c8233d2409a31206f78f9f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "86574b0ef7fbce15f208bf801866f34c664cf7ce"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "KOTO TRADE" and pe.signatures[i].serial=="02:96:85:cd:a1:c8:23:3d:24:09:a3:12:06:f7:8f:9f")
}
