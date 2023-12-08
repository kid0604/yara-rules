import "pe"

rule Reaver3_Malware_Nov17_2
{
	meta:
		description = "Detects Reaver malware mentioned in PaloAltoNetworks report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-new-malware-with-ties-to-sunorcal-discovered/"
		date = "2017-11-11"
		modified = "2023-01-06"
		hash1 = "9213f70bce491991c4cbbbd7dc3e67d3a3d535b965d7064973b35c50f265e59b"
		hash2 = "98eb5465c6330b9b49df2e7c9ad0b1164aa5b35423d9e80495a178eb510cdc1c"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "WindowsUpdateReaver" fullword wide
		$s1 = "\\WUpdate.~tmp" ascii
		$s2 = "\\~WUpdate.lnk" ascii
		$s3 = "\\services\\" ascii
		$s4 = "moomjufps" fullword ascii
		$s5 = "gekmomkege" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and (pe.imphash()=="837cc5062a0758335b257ea3b27972b2" or 1 of ($x*) or 3 of them )
}
