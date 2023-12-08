import "pe"

rule Reaver3_Malware_Nov17_1
{
	meta:
		description = "Detects Reaver malware mentioned in PaloAltoNetworks report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-new-malware-with-ties-to-sunorcal-discovered/"
		date = "2017-11-11"
		hash1 = "1813f10bcf74beb582c824c64fff63cb150d178bef93af81d875ca84214307a1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "CPL.dll" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and pe.imphash()=="e722dd50a0e2bc0cab8ca35fc4bf6d99" and all of them )
}
