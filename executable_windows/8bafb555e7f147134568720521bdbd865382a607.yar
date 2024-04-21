rule ADGet
{
	meta:
		description = "ADGet.exe"
		author = "_pete_0, TheDFIRReport"
		reference = "https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware"
		date = "2023-04-02"
		hash1 = "FC4DA07183DE876A2B8ED1B35EC1E2657400DA9D99A313452162399C519DBFC6"
		os = "windows"
		filetype = "executable"

	strings:
		$app1 = "AdGet <zip-file> [OPTIONS]" fullword ascii
		$app2 = "Exports data from Active Directory" fullword ascii
		$ldap1 = "PrimaryGroupID=516" fullword ascii
		$ldap2 = "PrimaryGroupID=521" fullword ascii
		$ldap3 = "objectClass=trustedDomain" fullword ascii

	condition:
		uint16(0)==0x5A4D and filesize <800KB and all of ($app*) and all of ($ldap*)
}
