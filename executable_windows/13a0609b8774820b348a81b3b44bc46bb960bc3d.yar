rule PUA_VULN_Driver_Yyinc_Dianhu_80CB
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - Dh_Kernel_10.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "80cbba9f404df3e642f22c476664d63d7c229d45d34f5cd0e19c65eb41becec3"
		hash = "bb50818a07b0eb1bd317467139b7eb4bad6cd89053fecdabfeae111689825955"
		date = "2023-06-14"
		score = 40
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]006400690061006e00680075 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]0059005900200049006e0063002e }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0030002e00390039 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0030002e00390039 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]006400690061006e00680075 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000a900200032003000300037002d003200300031003700200059005900200049006e0063002e00200041006c006c0020007200690067006800740073002000720065007300650072007600650064002e }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
