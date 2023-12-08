import "pe"

rule INDICATOR_KB_CERT_00d3d74ae548830d5b1bca9856e16c564a
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "3f996b75900d566bc178f36b3f4968e2a08365e8"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Insite Software Inc." and pe.signatures[i].serial=="00:d3:d7:4a:e5:48:83:0d:5b:1b:ca:98:56:e1:6c:56:4a")
}
