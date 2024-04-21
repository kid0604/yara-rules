rule case_15184_dontsleep
{
	meta:
		description = "15184_ - file dontsleep.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/"
		date = "2022-11-28"
		hash1 = "f8cff7082a936912baf2124d42ed82403c75c87cb160553a7df862f8d81809ee"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "shell32.dll,Control_RunDLL" fullword ascii
		$s2 = "powrprof.DLL" fullword wide
		$s3 = "CREATEPROCESS_MANIFEST_RESOURCE_ID RT_MANIFEST \"res\\\\APP.exe.manifest\"" fullword ascii
		$s4 = "msinfo32.exe" fullword ascii
		$s5 = "user32.dll,LockWorkStation" fullword wide
		$s6 = "DontSleep.exe" fullword wide
		$s7 = "UMServer.log" fullword ascii
		$s8 = "_Autoupdate.exe" fullword ascii
		$s9 = "BlockbyExecutionState: %d on:%d by_enable:%d" fullword wide
		$s10 = "powrprof.dll,SetSuspendState" fullword wide
		$s11 = "%UserProfile%" fullword wide
		$s12 = " 2010-2019 Nenad Hrg SoftwareOK.com" fullword wide
		$s13 = "https://sectigo.com/CPS0C" fullword ascii
		$s14 = "https://sectigo.com/CPS0D" fullword ascii
		$s15 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
		$s16 = "Unable to get response from Accept Thread withing specified Timeout ->" fullword ascii
		$s17 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
		$s18 = "Unable to get response from Helper Thread within specified Timeout ->" fullword ascii
		$s19 = "   <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\">" fullword ascii
		$s20 = "_selfdestruct.bat" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <700KB and 8 of them
}
