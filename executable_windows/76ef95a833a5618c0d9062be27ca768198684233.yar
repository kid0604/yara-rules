import "pe"

rule INDICATOR_KB_CERT_7ddd3796a427b42f2e52d7c7af0ca54f
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "b5cd5a485dee4a82f34c98b3f108579e8501fdea"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "OOO Fobos" and pe.signatures[i].serial=="7d:dd:37:96:a4:27:b4:2f:2e:52:d7:c7:af:0c:a5:4f")
}
