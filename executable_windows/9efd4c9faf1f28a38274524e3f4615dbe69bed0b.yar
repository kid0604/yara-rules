import "pe"

rule INDICATOR_KB_CERT_ca646b4275406df639cf603756f63d77
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "2a68cfad2d82caae48d4dcbb49aa73aaf3fe79dd"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "SHOECORP LIMITED" and (pe.signatures[i].serial=="ca:64:6b:42:75:40:6d:f6:39:cf:60:37:56:f6:3d:77" or pe.signatures[i].serial=="00:ca:64:6b:42:75:40:6d:f6:39:cf:60:37:56:f6:3d:77"))
}
