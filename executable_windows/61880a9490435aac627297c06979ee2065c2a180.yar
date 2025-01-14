rule PUA_VULN_Driver_Powertool_Kevpsys_Powertool_7C0F
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - kEvP64.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "7c0f77d103015fc29379ba75d133dc3450d557b0ba1f7495c6b43447abdae230"
		hash = "d9500af86bf129d06b47bcfbc4b23fcc724cfbd2af58b03cdb13b26f8f50d65e"
		hash = "2a4f4400402cdc475d39389645ca825bb0e775c3ecb7c527e30c5be44e24af7d"
		hash = "8e6363a6393eb4234667c6f614b2072e33512866b3204f8395bbe01530d63f2f"
		hash = "09b0e07af8b17db1d896b78da4dd3f55db76738ee1f4ced083a97d737334a184"
		hash = "e61004335dfe7349f2b2252baa1e111fb47c0f2d6c78a060502b6fcc92f801e4"
		hash = "7462b7ae48ae9469474222d4df2f0c4f72cdef7f3a69a524d4fccc5ed0fd343f"
		hash = "97363f377aaf3c01641ac04a15714acbec978afb1219ac8f22c7e5df7f2b2d56"
		hash = "1aaa9aef39cb3c0a854ecb4ca7d3b213458f302025e0ec5bfbdef973cca9111c"
		date = "2024-08-07"
		score = 40
		id = "b4eb0239-e787-50d8-bac9-78178e245bb8"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0050006f0077006500720054006f006f006c }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0050006f0077006500720054006f006f006c }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0030002e0031002e00300020006200750069006c0074002000620079003a002000570069006e00440044004b }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0030002e0031002e0030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]006b00450076005000360034002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0050006f0077006500720054006f006f006c }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]006b00450076005000360034002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0050006f0077006500720054006f006f006c }

	condition:
		uint16(0)==0x5a4d and filesize <2900KB and all of them
}
