rule PUA_VULN_Driver_Hilschergesellschaftfrsystemaoutomationmbh_Physmemsys_Physicalmemoryaccessdriver_C299
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - physmem.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "c299063e3eae8ddc15839767e83b9808fd43418dc5a1af7e4f44b97ba53fbd3d"
		date = "2023-06-14"
		score = 40
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0050006800790073006900630061006c0020004d0065006d006f0072007900200041006300630065007300730020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]00480069006c0073006300680065007200200047006500730065006c006c0073006300680061006600740020006600fc0072002000530079007300740065006d0061006f00750074006f006d006100740069006f006e0020006d00620048 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0030002e0030002e0030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0030002e0030002e0030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]0070006800790073006d0065006d002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0050006800790073006900630061006c0020004d0065006d006f0072007900200041006300630065007300730020004400720069007600650072 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]0070006800790073006d0065006d002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]00a9002000480069006c0073006300680065007200200047006500730065006c006c0073006300680061006600740020006600fc0072002000530079007300740065006d0061006f00750074006f006d006100740069006f006e0020006d00620048002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}