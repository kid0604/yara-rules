import "pe"

rule INDICATOR_KB_CERT_25a28e418ef2d55b87ee715b42afbedb
{
	meta:
		author = "ditekSHen"
		description = "VMProtect Software CA Certificate"
		thumbprint = "14e375bd4a40ddd3310e05328dda16e84bac6d34"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Enigma Protector CA" and pe.signatures[i].serial=="25:a2:8e:41:8e:f2:d5:5b:87:ee:71:5b:42:af:be:db")
}
