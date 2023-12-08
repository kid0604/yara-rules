rule PUA_VULN_Driver_Corsairmemoryinc_Corsairllaccess_Corsairllaccess_F15A
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - CorsairLLAccess64.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "f15ae970e222ce06dbf3752b223270d0e726fb78ebec3598b4f8225b5a0880b1"
		date = "2023-06-14"
		score = 40
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]0043006f007200730061006900720020004c004c0020004100630063006500730073 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0043006f007200730061006900720020004d0065006d006f00720079002c00200049006e0063002e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0030002e00310035002e0030 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0030002e00310035002e0030 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]0043006f007200730061006900720020004c004c0020004100630063006500730073 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0043006f007200730061006900720020004c004c0020004100630063006500730073 }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]0043006f007200730061006900720020004c004c0020004100630063006500730073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f007200730061006900720020004d0065006d006f00720079002c00200049006e0063002e002000280063002900200032003000310039002c00200041006c006c0020007200690067006800740073002000720065007300650072007600650064 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
