rule PUA_VULN_Driver_Asustekcomputerinc_Eiosys_Asusvgakernelmodedriver_B175
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - EIO.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "b17507a3246020fa0052a172485d7b3567e0161747927f2edf27c40e310852e0"
		date = "2023-06-14"
		score = 40
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]004100530055005300200056004700410020004b00650072006e0065006c0020004d006f006400650020004400720069007600650072 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004100530055005300540065004b00200043006f006d0070007500740065007200200049006e0063002e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e00390036 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e00390036 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]00450049004f002e007300790073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]004100530055005300200056004700410020004b00650072006e0065006c0020004d006f006400650020004400720069007600650072 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]00450049004f002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000320030003000370020004100530055005300540065004b00200043006f006d0070007500740065007200200049006e0063002e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
