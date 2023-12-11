import "pe"

rule HackTool_MSIL_SharPivot_2
{
	meta:
		md5 = "e4efa759d425e2f26fbc29943a30f5bd"
		rev = 3
		author = "FireEye"
		description = "Detects the presence of HackTool MSIL SharPivot 2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "costura"
		$s2 = "cmd_schtask" wide
		$s3 = "cmd_wmi" wide
		$s4 = "cmd_rpc" wide
		$s5 = "GoogleUpdateTaskMachineUA" wide
		$s6 = "servicehijack" wide
		$s7 = "poisonhandler" wide

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}
