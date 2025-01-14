rule PUA_VULN_Driver_Asrockincorporation_Asrautochkupddrvsys_Asrautochkupddrvdriver_4AE4
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - AsrAutoChkUpdDrv_1_0_32.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "4ae42c1f11a98dee07a0d7199f611699511f1fb95120fabc4c3c349c485467fe"
		date = "2024-08-07"
		score = 40
		id = "64fed65f-7b98-54a9-b84d-00401c4e4094"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]004100730072004100750074006f00430068006b005500700064004400720076005f0031005f0030005f003300320020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004100530052006f0063006b00200049006e0063006f00720070006f0072006100740069006f006e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e00300030002e00300030002e00300030003000300020006200750069006c0074002000620079003a002000570069006e00440044004b }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e00300030002e00300030002e0030003000300030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]004100730072004100750074006f00430068006b005500700064004400720076005f0031005f0030005f00330032002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004100730072004100750074006f00430068006b005500700064004400720076005f0031005f0030005f003300320020004400720069007600650072 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]004100730072004100750074006f00430068006b005500700064004400720076005f0031005f0030005f00330032002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f00700079007200690067006800740020002800430029002000320030003100320020004100530052006f0063006b00200049006e0063006f00720070006f0072006100740069006f006e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
