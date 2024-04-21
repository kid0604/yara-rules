rule case_18543_demurest_cmd
{
	meta:
		description = "18543 - file demurest.cmd"
		author = "The DFIR Report via yarGen Rule Generator"
		reference = "https://thedfirreport.com/2023/08/28/html-smuggling-leads-to-domain-wide-ransomware/"
		date = "2023-08-28"
		hash1 = "364d346da8e398a89d3542600cbc72984b857df3d20a6dc37879f14e5e173522"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "echo f|xcopy %SystemRoot%\\system32\\%x1%%x2%%x3%.exe %temp%\\entails.exe /h /s /e" fullword ascii
		$s2 = "%temp%\\entails.exe %t3%,%xxx%" fullword ascii
		$s3 = "set t3=%temp%\\%random%.%random%" fullword ascii
		$s4 = "echo f|xcopy !exe1!!exe2! %t3% /h /s /e" fullword ascii
		$s5 = "if %random% neq 300 (" fullword ascii
		$s6 = "if %random% neq 100 (" fullword ascii
		$s7 = "set exe2=templ" fullword ascii
		$s8 = "if %random% neq 200 (" fullword ascii
		$s9 = "set exe1=ates544.png" fullword ascii
		$s10 = "start pimpliest_kufic.png" fullword ascii
		$s11 = "set x2=dll" fullword ascii
		$s12 = "set x3=run" fullword ascii
		$s13 = "SETLOCAL EnableDelayedExpansion" fullword ascii
		$s14 = "    set xxx=pimpliest_kufic.png" fullword ascii
		$s15 = ") else (" fullword ascii
		$s16 = "set x1=32" fullword ascii

	condition:
		uint16(0)==0x4553 and filesize <2KB and 1 of ($x*) and 4 of them
}
