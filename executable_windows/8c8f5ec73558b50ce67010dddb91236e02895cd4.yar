import "pe"

rule EquationGroup_EquationDrug_Gen_2
{
	meta:
		description = "EquationGroup Malware - file PortMap_Implant.dll"
		author = "Auto Generated"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		hash1 = "964762416840738b1235ed4ae479a4b117b8cdcc762a6737e83bc2062c0cf236"
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = { 0c 2b ca 8a 04 11 3a 02 75 01 47 42 4e 75 f4 8b }
		$op2 = { 14 83 c1 05 80 39 85 75 0c 80 79 01 c0 75 06 80 }
		$op3 = { eb 3d 83 c0 06 33 f6 80 38 ff 75 2c 80 78 01 15 }

	condition:
		( uint16(0)==0x5a4d and filesize <250KB and all of them )
}
