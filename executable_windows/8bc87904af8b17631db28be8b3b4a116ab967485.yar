rule case_19772_csrss_cobalt_strike
{
	meta:
		description = "19772 - file csrss.exe"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com/2024/04/01/from-onenote-to-ransomnote-an-ice-cold-intrusion"
		date = "2024-01-09"
		hash1 = "06bbb36baf63bc5cb14d7f097745955a4854a62fa3acef4d80c61b4fa002c542"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Invalid owner %s is already associated with %s=This control requires version 4.70 or greater of COMCTL32.DLL" fullword wide
		$s2 = "traydemo.exe" fullword ascii
		$s3 = "333330303030333333" ascii
		$s4 = "323232323233323232323233333333333333" ascii
		$s5 = "333333333333333333333333333333333333333333333333333333333333333333333333" ascii
		$s6 = "Borland C++ - Copyright 2002 Borland Corporation" fullword ascii
		$s7 = "@Cdiroutl@TCDirectoryOutline@GetChildNamed$qqrrx17System@AnsiStringl" fullword ascii
		$s8 = "2a1d2V1p1" fullword ascii
		$s9 = "Separator\"Unable to find a Table of Contents" fullword wide
		$s10 = "EInvalidGraphicOperation4" fullword ascii
		$s11 = ")Failed to read ImageList data from stream(Failed to write ImageList data to stream$Error creating window device context" fullword wide
		$s12 = "%s: %s error" fullword ascii
		$s13 = "@TTrayIcon@GetAnimate$qqrv" fullword ascii
		$s14 = "ImageTypeh" fullword ascii
		$s15 = "42464:4`4d4 3" fullword ascii
		$s16 = "333333333333333333333333(" fullword ascii
		$s17 = ")\"\")\"\")#3232" fullword ascii
		$s18 = "OnGetItem(3B" fullword ascii
		$s19 = "@Cspin@TCSpinEdit@GetValue$qqrv" fullword ascii
		$s20 = "@Cspin@TCSpinButton@GetUpGlyph$qqrv" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and 1 of ($x*) and 4 of them
}
