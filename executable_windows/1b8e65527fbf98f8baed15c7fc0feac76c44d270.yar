import "pe"

rule INDICATOR_KB_CERT_661ba8f3c9d1b348413484e9a49502f7
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "4ca944c9b69f72be3e95f385bdbc70fc7cff4c3ebb76a365bf0ab0126b277b2d"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Unique Digital Services Ltd." and pe.signatures[i].serial=="66:1b:a8:f3:c9:d1:b3:48:41:34:84:e9:a4:95:02:f7")
}
