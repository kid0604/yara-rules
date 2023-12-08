rule Ransom_CryptXXX_Dropper
{
	meta:
		description = "Regla para detectar RANSOM.CRYPTXXX"
		author = "CCN-CERT"
		version = "1.0"
		ref = "https://www.ccn-cert.cni.es/seguridad-al-dia/comunicados-ccn-cert/4002-publicado-el-informe-del-codigo-danino-ransom-cryptxxx.html"
		os = "windows"
		filetype = "executable"

	strings:
		$a = { 50 65 31 57 58 43 46 76 59 62 48 6F 35 }
		$b = { 43 00 3A 00 5C 00 42 00 49 00 45 00 52 00 5C 00 51 00 6D 00 6B 00 4E 00 52 00 4C 00 46 00 00 }

	condition:
		all of them
}
