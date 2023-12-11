rule PUA_VULN_Driver_Elaboratebytesag_Elbycdio_Cdrtools_2FBB
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - ElbyCDIO.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "2fbbc276737047cb9b3ba5396756d28c1737342d89dce1b64c23a9c4513ae445"
		date = "2023-06-14"
		score = 40
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0045006c0062007900430044002000570069006e0064006f007700730020004e0054002f0032003000300030002f0058005000200049002f004f0020006400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0045006c00610062006f0072006100740065002000420079007400650073002000410047 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0036002c00200030002c00200030002c00200032 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0036002c00200030002c00200030002c00200030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]0045006c00620079004300440049004f }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0043004400520054006f006f006c0073 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]0045006c00620079004300440049004f002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f00700079007200690067006800740020002800430029002000320030003000300020002d0020003200300030003700200045006c00610062006f0072006100740065002000420079007400650073002000410047 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
