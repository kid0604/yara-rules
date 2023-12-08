import "pe"

rule INDICATOR_KB_CERT_15da61d7e1a631803431561674fb9b90
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "9a9bc3974e3cbbabdeb2b6debdc0455586e128a4"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "JAY DANCE STUDIO d.o.o." and pe.signatures[i].serial=="15:da:61:d7:e1:a6:31:80:34:31:56:16:74:fb:9b:90")
}
