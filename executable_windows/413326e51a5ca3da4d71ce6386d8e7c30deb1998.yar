import "pe"

rule INDICATOR_KB_CERT_58aa64564a50e8b2d6e31d5cd6250fde
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "a7b43a5190e6a72c68e20f661f69ddc24b5a2561"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Foreground" and pe.signatures[i].serial=="58:aa:64:56:4a:50:e8:b2:d6:e3:1d:5c:d6:25:0f:de")
}
