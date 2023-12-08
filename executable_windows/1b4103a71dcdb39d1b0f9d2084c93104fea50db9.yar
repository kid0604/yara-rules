import "pe"

rule INDICATOR_KB_CERT_7ab21306b11ff280a93fc445876988ab
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "6d0d10933b355ee2d8701510f22aff4a06adbe5b"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "ABC BIOS d.o.o." and pe.signatures[i].serial=="7a:b2:13:06:b1:1f:f2:80:a9:3f:c4:45:87:69:88:ab")
}
