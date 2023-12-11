import "pe"

rule INDICATOR_KB_CERT_39f56251df2088223cc03494084e6081
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "66f32cf78b8f685a2c6f5bf361c9b0f9a9678de11a8e7931e2205d0ef65af05c"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Inter Med Pty. Ltd." and pe.signatures[i].serial=="39:f5:62:51:df:20:88:22:3c:c0:34:94:08:4e:60:81")
}
