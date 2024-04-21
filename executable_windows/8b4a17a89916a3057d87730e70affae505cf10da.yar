rule __case_5295_check
{
	meta:
		description = "5295 - file check.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com"
		date = "2021-08-12"
		hash1 = "c443df1ddf8fd8a47af6fbfd0b597c4eb30d82efd1941692ba9bb9c4d6874e14"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
		$s2 = "F:\\Source\\WorkNew18\\CheckOnline\\Release\\CheckOnline.pdb" fullword ascii
		$s3 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
		$s4 = " Type Descriptor'" fullword ascii
		$s5 = "operator co_await" fullword ascii
		$s6 = "operator<=>" fullword ascii
		$s7 = ".data$rs" fullword ascii
		$s8 = "File opening error: " fullword ascii
		$s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
		$s10 = ":0:8:L:\\:h:" fullword ascii
		$s11 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		$s12 = " Base Class Descriptor at (" fullword ascii
		$s13 = " Class Hierarchy Descriptor'" fullword ascii
		$s14 = " Complete Object Locator'" fullword ascii
		$s15 = "network reset" fullword ascii
		$s16 = "connection already in progress" fullword ascii
		$s17 = "wrong protocol type" fullword ascii
		$s18 = "network down" fullword ascii
		$s19 = "owner dead" fullword ascii
		$s20 = "protocol not supported" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and all of them
}
