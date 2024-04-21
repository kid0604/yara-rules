rule case_19438_files_MalFiles_pcicapi
{
	meta:
		description = "19438 - file pcicapi.dll"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
		date = "2023-10-29"
		hash1 = "2d6c6200508c0797e6542b195c999f3485c4ef76551aa3c65016587788ba1703"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "CAPI2032.DLL" fullword ascii
		$s2 = "pcicapi.dll" fullword wide
		$s3 = "Assert failed - " fullword ascii
		$s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
		$s5 = "E:\\nsmsrc\\nsm\\1210\\1210\\ctl32\\Release\\pcicapi.pdb" fullword ascii
		$s6 = "Received unexpected CAPI message, command=%x, plci=%d, ncci=%d" fullword ascii
		$s7 = "Unhandled Exception (GPF) - " fullword ascii
		$s8 = "NSMTraceGetConfigItem" fullword ascii
		$s9 = "NSMTraceGetConfigInt" fullword ascii
		$s10 = "File %hs, line %d%s%s" fullword ascii
		$s11 = "NSMTraceReadConfigItemFromFile" fullword ascii
		$s12 = "Assert, tid=%x%s" fullword ascii
		$s13 = "!\"Could not stop CAPI GetMsgThread\"" fullword ascii
		$s14 = ", thread=%s" fullword ascii
		$s15 = "NetSupport Ltd0" fullword ascii
		$s16 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
		$s17 = "Support\\" fullword ascii
		$s18 = ", error code %u (x%x)" fullword ascii
		$s19 = "NetSupport Ltd1" fullword ascii
		$s20 = "NetSupport Ltd" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 8 of them
}
