import "pe"

rule INDICATOR_KB_CERT_2aaa455a172f7e3a2dffb5c6b14f9c16
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "23c91b66bd07e56e60724b0064d4fedbdb1c8913"
		hash1 = "7852cf2dfe60b60194dae9b037298ed0a9c84fa1d850f3898751575f4377215f"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "DREAM VILLAGE s.r.o." and pe.signatures[i].serial=="2a:aa:45:5a:17:2f:7e:3a:2d:ff:b5:c6:b1:4f:9c:16")
}
