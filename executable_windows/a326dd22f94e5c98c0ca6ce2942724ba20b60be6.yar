rule yara_tor2mine
{
	meta:
		description = "file java.exe"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/"
		date = "2023-12-02"
		hash1 = "74b6d14e35ff51fe47e169e76b4732b9f157cd7e537a2ca587c58dbdb15c624f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
		$s2 = "3~\"0\\25" fullword ascii
		$s3 = "X'BF:\"" fullword ascii
		$s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
		$s5 = "<BiNHQZG?" fullword ascii
		$s6 = "5%d:8\\" fullword ascii
		$s7 = "tJohdy7" fullword ascii
		$s8 = "0- vuyT]" fullword ascii
		$s9 = "wpeucv" fullword ascii
		$s10 = "kreczd" fullword ascii
		$s11 = "%DeK%o" fullword ascii
		$s12 = "i%eI%xS" fullword ascii
		$s13 = "s -mY'" fullword ascii
		$s14 = "mCVAvi2" fullword ascii
		$s15 = "**[Zu -" fullword ascii
		$s16 = "%TNz%_\"V" fullword ascii
		$s17 = " -reB6" fullword ascii
		$s18 = "OD.vbpyW" fullword ascii
		$s19 = ":I* &b" fullword ascii
		$s20 = "R?%Y%l" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and 8 of them
}
