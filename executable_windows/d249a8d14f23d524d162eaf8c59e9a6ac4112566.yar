rule PUA_VULN_Driver_Trendmicroinc_Tmcommsys_Trendmicroeyes_6FFD
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - TmComm.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "6ffdde6bc6784c13c601442e47157062941c47015891e7139c2aaba676ab59cc"
		date = "2023-06-14"
		score = 40
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]005400720065006e0064004d006900630072006f00200043006f006d006d006f006e0020004d006f00640075006c00650020004e006f00540072006100700020004200750069006c0064 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]005400720065006e00640020004d006900630072006f00200049006e0063002e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0035002e0030002e0030002e0031003100300034 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0035002e0030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]0054006d0043006f006d006d002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]005400720065006e00640020004d006900630072006f00200045007900650073 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]0054006d0043006f006d006d002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000280043002900200032003000300035002d00320030003100310020005400720065006e00640020004d006900630072006f00200049006e0063006f00720070006f00720061007400650064002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
