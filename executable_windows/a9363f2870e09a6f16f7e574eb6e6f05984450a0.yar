import "pe"

rule INDICATOR_KB_CERT_00f675139ea68b897a865a98f8e4611f00
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "06d46ee9037080c003983d76be3216b7cad528f8"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "BS TEHNIK d.o.o." and pe.signatures[i].serial=="00:f6:75:13:9e:a6:8b:89:7a:86:5a:98:f8:e4:61:1f:00")
}
