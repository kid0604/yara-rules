rule Ransom_Stop_2
{
	meta:
		description = "Detect the risk of Ransomware STOP Rule 4"
		os = "windows"
		filetype = "executable"

	strings:
		$op1 = {003145F833C5508D45F064A300000000837D08007505E9980000006A04E8????000083C404C745FC000000008B450883E8208945E48B4DE48B511481E2FFFF}
		$op2 = {000083C404C38B4DF064890D00000000595F5E5B8BE55DC3CCCCCCCCCCCCCC}
		$s1 = {0000000000420075007300750068006F0070006500640000004C006F00760061006A00200062006900760065007800610070006F006A00650068000000}

	condition:
		uint16(0)==0x5a4d and all of them
}