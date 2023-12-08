import "pe"

rule MALWARE_Win_DLAgent14
{
	meta:
		author = "ditekSHen"
		description = "Detects downloader injector"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%ProgramData%\\AVG" fullword wide
		$s2 = "%ProgramData%\\AVAST Software" fullword wide
		$s3 = "%wS\\%wS.vbs" fullword wide
		$s4 = "%wS\\%wS.exe" fullword wide
		$s5 = "CL,FR,US,CY,FI,HR,HU,RO,PL,IT,PT,ES,CA,DK,AT,NL,AU,AR,NP,SE,BE,NZ,SK,GR,BG,NO,GE" ascii
		$s6 = "= CreateObject(\"Microsoft.XMLHTTP\")" ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}
