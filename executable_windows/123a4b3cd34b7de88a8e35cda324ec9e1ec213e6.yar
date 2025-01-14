rule PUA_VULN_Driver_Cn_Computerzsys_3913
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - ComputerZ.Sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "39134750f909987f6ebb46cf37519bb80707be0ca2017f3735018bac795a3f8d"
		hash = "a34e45e5bbec861e937aefb3cbb7c8818f72df2082029e43264c2b361424cbb1"
		hash = "3e758221506628b116e88c14e71be99940894663013df3cf1a9e0b6fb18852b9"
		date = "2024-08-07"
		score = 40
		id = "26b781e0-c148-5506-b135-9b0b8fbf7cf3"
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]004c007500640061007300680069002000530079007300740065006d0020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]003300360030002e0063006e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0036002e00310031002e003400310035 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0036002e00310031002e003400310035 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]0043006f006d00700075007400650072005a002e005300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]003300360030786c4ef659275e08 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]0043006f006d00700075007400650072005a002e005300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]7248674362406709002000280043002900200032003000310030002d00320030003100310020003300360030002e0063006e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
