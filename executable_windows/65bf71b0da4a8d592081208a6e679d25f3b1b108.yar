import "pe"

rule INDICATOR_KB_CERT_9fac361ee3304079
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "2168032804def9cdbc1fc1a669377d494832f4ec"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "2021945 Ontario Inc." and (pe.signatures[i].serial=="9f:ac:36:1e:e3:30:40:79" or pe.signatures[i].serial=="00:9f:ac:36:1e:e3:30:40:79"))
}
