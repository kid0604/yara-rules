rule PUA_VULN_Driver_Huawei_Hwosec_Huaweimatebook_B179
{
	meta:
		description = "Detects vulnerable driver mentioned in LOLDrivers project using VersionInfo values from the PE header - HwOs2Ec7x64.sys"
		author = "Florian Roth"
		reference = "https://github.com/magicsword-io/LOLDrivers"
		hash = "b179e1ab6dc0b1aee783adbcad4ad6bb75a8a64cb798f30c0dd2ee8aaf43e6de"
		hash = "bb1135b51acca8348d285dc5461d10e8f57260e7d0c8cc4a092734d53fc40cbc"
		date = "2023-06-14"
		score = 40
		os = "windows"
		filetype = "executable"

	strings:
		$ = { 00460069006c0065004400650073006300720069007000740069006f006e[1-8]00480077004f0073003200450063 }
		$ = { 0043006f006d00700061006e0079004e0061006d0065[1-8]004800750061007700650069 }
		$ = { 00460069006c006500560065007200730069006f006e[1-8]0031002e0030002e0030002e0031 }
		$ = { 00500072006f006400750063007400560065007200730069006f006e[1-8]0031002e0030002e0030002e0031 }
		$ = { 0049006e007400650072006e0061006c004e0061006d0065[1-8]00480077004f0073003200450063 }
		$ = { 00500072006f0064007500630074004e0061006d0065[1-8]0048007500610077006500690020004d0061007400650042006f006f006b }
		$ = { 004f0072006900670069006e0061006c00460069006c0065006e0061006d0065[1-8]00480077004f0073003200450063002e007300790073 }
		$ = { 004c006500670061006c0043006f0070007900720069006700680074[1-8]0043006f0070007900720069006700680074002000280043002900200032003000310036 }

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
