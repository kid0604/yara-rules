import "pe"

rule INDICATOR_KB_CERT_5b440a47e8ce3dd202271e5c7a666c78
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "07e4cbdd52027e38b86727e88b33a0a1d49fe18f5aee4101353dd371d7a28da5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Master Networking s.r.o." and pe.signatures[i].serial=="5b:44:0a:47:e8:ce:3d:d2:02:27:1e:5c:7a:66:6c:78")
}
