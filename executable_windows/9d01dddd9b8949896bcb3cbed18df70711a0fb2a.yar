rule case_19438_files_MalFiles_PCICHEK
{
	meta:
		description = "19438 - file PCICHEK.DLL"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
		date = "2023-10-29"
		hash1 = "956b9fa960f913cce3137089c601f3c64cc24c54614b02bba62abb9610a985dd"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "pcichek.dll" fullword wide
		$s2 = "E:\\nsmsrc\\nsm\\1210\\1210f\\ctl32\\Full\\pcichek.pdb" fullword ascii
		$s3 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
		$s4 = "The %s license file (NSM.LIC) has been hacked.  Action is being taken against the perpetrators.  Please use the evaluation versi" wide
		$s5 = "This is an evaluation copy of %s and can only be used with an evaluation license file (NSM.LIC).  Please contact your vendor for" wide
		$s6 = "654321" ascii
		$s7 = "4%4.4A4^4" fullword ascii
		$s8 = "pcichek" fullword wide
		$s9 = "NetSupport Ltd0" fullword ascii
		$s10 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
		$s11 = "NetSupport Ltd1" fullword ascii
		$s12 = "!Copyright (c) 2016 NetSupport Ltd" fullword wide
		$s13 = "NetSupport Ltd" fullword wide
		$s14 = "Copyright (c) 2016, NetSupport Ltd" fullword wide
		$s15 = "NetSupport Manager" fullword wide
		$s16 = "NetSupport pcichek" fullword wide
		$s17 = "!!!!:23/09/16 15:51:38 V12.10F18" fullword ascii
		$s18 = "Peterborough1" fullword ascii
		$s19 = "  </trustInfo>" fullword ascii
		$s20 = "CheckLicenseString" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <60KB and 8 of them
}
