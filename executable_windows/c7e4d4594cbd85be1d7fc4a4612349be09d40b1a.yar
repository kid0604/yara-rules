rule PUA_VULN_Driver_Tgsoftsas_Viragtsys_Viritagentsystem_E4EC
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - viragt64.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "e4eca7db365929ff7c5c785e2eab04ef8ec67ea9edcf7392f2b74eccd9449148"
		date = "2023-06-14"
		score = 40
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]005600690072004900540020004100670065006e0074002000530079007300740065006d }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0054004700200053006f0066007400200053002e0061002e0073002e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002c002000330038002c00200030002c00200030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002c002000330038002c00200030002c00200030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]007600690072006100670074002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]005600690072004900540020004100670065006e0074002000530079007300740065006d }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]007600690072006100670074002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000280043002900200054004700200053006f0066007400200053002e0061002e0073002e00200032003000300036002c002000320030003100310020002d0020007700770077002e007400670073006f00660074002e00690074 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
