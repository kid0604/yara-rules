rule EquationGroup_Toolset_Apr17__LSADUMP_Lp_ModifyPrivilege_Lp_PacketScan_Lp_put_Lp_RemoteExecute_Lp_Windows_Lp_wmi_Lp_9
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		date = "2017-04-15"
		super_rule = 1
		hash1 = "c7bf4c012293e7de56d86f4f5b4eeb6c1c5263568cc4d9863a286a86b5daf194"
		hash2 = "d92928a867a685274b0a74ec55c0b83690fca989699310179e184e2787d47f48"
		hash3 = "2d963529e6db733c5b74db1894d75493507e6e40da0de2f33e301959b50f3d32"
		hash4 = "e9f6a84899c9a042edbbff391ca076169da1a6f6dfb61b927942fe4be3327749"
		hash5 = "d989d610b032c72252a2df284d0b53f63f382e305de2a18b453a0510ab6246a3"
		hash6 = "23d98bca1f6e2f6989d53c2f2adff996ede2c961ea189744f8ae65621003b8b1"
		hash7 = "d7ae24816fda190feda6a60639cf3716ea00fb63a4bd1069b8ce52d10ad8bc7f"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Injection Lib -  " wide
		$x2 = "LSADUMP - - ERROR" wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 1 of them )
}
