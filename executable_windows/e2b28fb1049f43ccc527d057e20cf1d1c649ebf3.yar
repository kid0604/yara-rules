import "pe"

rule INDICATOR_KB_CERT_00a7989f8be0c82d35a19e7b3dd4be30e5
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "3e93aadb509b542c065801f04cffb34956f84ee8c322d65c7ae8e23d27fe5fbf"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Instamix Limited" and pe.signatures[i].serial=="00:a7:98:9f:8b:e0:c8:2d:35:a1:9e:7b:3d:d4:be:30:e5")
}
