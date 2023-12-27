rule PUA_VULN_Driver_Micsystechnologycoltd_Msiosys_Msiodriverversion_X_CFCF
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - MsIo64.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "cfcf32f5662791f1f22a77acb6dddfbc970fe6e99506969b3ea67c03f67687ab"
		date = "2023-06-14"
		score = 40
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]004d0049004300530059005300200049004f0020006400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004d0049004300530059005300200054006500630068006e006f006c006f0067007900200043006f002e002c0020004c00540064 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e003200200078003600340020006200750069006c0074002000620079003a002000570069006e00440044004b }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e00320020007800360034 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]004d00730049006f00360034002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004d00730049006f003600340020004400720069007600650072002000560065007200730069006f006e00200031002e0032 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]004d00730049006f00360034002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f00700079007200690067006800740020002800630029002000320030003100390020004d00490043005300590053 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}