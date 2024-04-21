rule case_12993_cve_2021_44077_msiexec
{
	meta:
		description = "Files - file msiexec.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2022/06/06/will-the-real-msiexec-please-stand-up-exploit-leads-to-data-exfiltration/"
		date = "2022-06-06"
		hash1 = "4d8f797790019315b9fac5b72cbf693bceeeffc86dc6d97e9547c309d8cd9baf"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "C:\\Users\\Administrator\\msiexec\\msiexec\\msiexec\\obj\\x86\\Debug\\msiexec.pdb" fullword ascii
		$x2 = "M:\\work\\Shellll\\msiexec\\msiexec\\obj\\Release\\msiexec.pdb" fullword ascii
		$s2 = "..\\custom\\login\\fm2.jsp" fullword wide
		$s3 = "Qk1QDQo8JUBwYWdlIGltcG9ydD0iamF2YS51dGlsLnppcC5aaXBFbnRyeSIlPg0KPCVAcGFnZSBpbXBvcnQ9ImphdmEudXRpbC56aXAuWmlwT3V0cHV0U3RyZWFtIiU+" wide
		$s4 = "Program" fullword ascii
		$s5 = "Encoding" fullword ascii
		$s6 = "base64EncodedData" fullword ascii
		$s7 = "System.Runtime.CompilerServices" fullword ascii
		$s8 = "System.Reflection" fullword ascii
		$s9 = "System" fullword ascii
		$s10 = "Base64Decode" fullword ascii
		$s11 = "$77b5d0d3-047f-4017-a788-503ab92444a7" fullword ascii
		$s12 = "  2021" fullword wide
		$s13 = "RSDSv_" fullword ascii
		$s14 = "503ab92444a7" ascii
		$s15 = "q.#z.+" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <90KB and 1 of ($x*) and 4 of them
}
