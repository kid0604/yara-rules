rule gozi_17386_6570872_lnk
{
	meta:
		description = "Gozi - file 6570872.lnk"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts"
		date = "2023-01-08"
		hash1 = "c6b605a120e0d3f3cbd146bdbc358834"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "..\\..\\..\\..\\me\\alsoOne.bat" fullword wide
		$s2 = "alsoOne.bat" fullword wide
		$s3 = "c:\\windows\\explorer.exe" fullword wide
		$s4 = "%SystemRoot%\\explorer.exe" fullword wide

	condition:
		uint16(0)==0x004c and filesize <4KB and all of them
}
