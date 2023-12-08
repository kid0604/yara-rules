import "pe"

rule INDICATOR_KB_CERT_19f613cf951d49814250701037442ee2
{
	meta:
		author = "ditekSHen"
		description = "Detects executables signed with stolen, revoked or invalid certificates"
		thumbprint1 = "6feab07fa782fc7fbddde8465815f4d04d79ad97"
		thumbprint2 = "41aaafa56a30badb291e96d31ed15a9343ba7ed3"
		hash1 = "9629cae6d009dadc60e49f5b4a492bd1169d93f17afa76bee27c37be5bca3015"
		hash2 = "3b3281feef6d8e0eda2ab7232bd93f7c747bee143c2dfce15d23a1869bf0eddf"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and for any i in (0..pe.number_of_signatures) : (pe.signatures[i].subject contains "Cooler Master" and (pe.signatures[i].serial=="19:f6:13:cf:95:1d:49:81:42:50:70:10:37:44:2e:e2" or pe.signatures[i].serial=="6b:e8:ee:f0:82:a4:f5:96:4c:75:0b:c0:07:24:f6:4a"))
}
