import "pe"

rule INDICATOR_KB_CERT_00bdb99d5ecf8271d48e35f1039c2160ef
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint = "331f96a1a187723eaa5b72c9d0115c1c57f08b66"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Gavrilov Andrei Alekseevich" and (pe.signatures[i].serial=="bd:b9:9d:5e:cf:82:71:d4:8e:35:f1:03:9c:21:60:ef" or pe.signatures[i].serial=="00:bd:b9:9d:5e:cf:82:71:d4:8e:35:f1:03:9c:21:60:ef"))
}
