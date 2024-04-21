rule conti_dll_9438
{
	meta:
		description = "9438 - file x64.dll"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com/2022/04/04/stolen-images-campaign-ends-in-conti-ransomware/"
		date = "2022-04-04"
		hash1 = "8fb035b73bf207243c9b29d96e435ce11eb9810a0f4fdcc6bb25a14a0ec8cc21"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "AppPolicyGetProcessTerminationMethod" fullword ascii
		$s2 = "conti_v3.dll" fullword ascii
		$s3 = "        <requestedExecutionLevel level='asInvoker' uiAccess='false' />" fullword ascii
		$s4 = "api-ms-win-core-processthreads-l1-1-2" fullword wide
		$s5 = "ext-ms-win-ntuser-dialogbox-l1-1-0" fullword wide
		$s6 = " Type Descriptor'" fullword ascii
		$s7 = "operator \"\" " fullword ascii
		$s8 = "operator co_await" fullword ascii
		$s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
		$s10 = "api-ms-win-rtcore-ntuser-window-l1-1-0" fullword wide
		$s11 = "api-ms-win-security-systemfunctions-l1-1-0" fullword wide
		$s12 = "ext-ms-win-ntuser-windowstation-l1-1-0" fullword wide
		$s13 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
		$s14 = " Base Class Descriptor at (" fullword ascii
		$s15 = " Class Hierarchy Descriptor'" fullword ascii
		$s16 = "bad array new length" fullword ascii
		$s17 = " Complete Object Locator'" fullword ascii
		$s18 = ".data$r" fullword ascii
		$s19 = " delete[]" fullword ascii
		$s20 = "  </trustInfo>" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and all of them
}
