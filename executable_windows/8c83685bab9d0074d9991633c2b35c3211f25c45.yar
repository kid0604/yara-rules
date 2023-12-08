import "pe"

rule INDICATOR_KB_CERT_738db9460a10bb8bc03dc59feac3be5e
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4cf77e598b603c13cdcd1a676ca61513558df746"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Jocelyn Bennett" and pe.signatures[i].serial=="73:8d:b9:46:0a:10:bb:8b:c0:3d:c5:9f:ea:c3:be:5e")
}
