import "pe"

rule MALWARE_Win_HoudiniConfig
{
	meta:
		author = "ditekshen"
		description = "Detects Houdini Trojan configurations"
		reference = "https://github.com/ditekshen/back-in-2017"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "install_name="
		$s2 = "nick_name="
		$s3 = "install_folder="
		$s4 = "reg_startup="
		$s5 = "startup_folder_startup="
		$s6 = "task_startup="
		$s7 = "injection="
		$s8 = "injection_process"

	condition:
		( uint16(0)==0x5a4d and 5 of them ) or ( all of them )
}
