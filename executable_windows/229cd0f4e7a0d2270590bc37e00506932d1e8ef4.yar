import "pe"

rule INDICATOR_KB_CERT_4c687a0022c36f89e253f91d1f6954e2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4412007ae212d12cea36ed56985bd762bd9fb54a"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "HETCO ApS" and pe.signatures[i].serial=="4c:68:7a:00:22:c3:6f:89:e2:53:f9:1d:1f:69:54:e2")
}
