import "pe"

rule APT_HackTool_MSIL_WMISPY_2
{
	meta:
		description = "wql searches"
		md5 = "3651f252d53d2f46040652788499d65a"
		rev = 4
		author = "FireEye"
		os = "windows"
		filetype = "executable"

	strings:
		$MSIL = "_CorExeMain"
		$str1 = "root\\cimv2" wide
		$str2 = "root\\standardcimv2" wide
		$str3 = "from MSFT_NetNeighbor" wide
		$str4 = "from Win32_NetworkLoginProfile" wide
		$str5 = "from Win32_IP4RouteTable" wide
		$str6 = "from Win32_DCOMApplication" wide
		$str7 = "from Win32_SystemDriver" wide
		$str8 = "from Win32_Share" wide
		$str9 = "from Win32_Process" wide

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and $MSIL and all of ($str*)
}
