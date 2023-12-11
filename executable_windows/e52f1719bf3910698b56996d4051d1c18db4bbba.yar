import "pe"

rule MALWARE_Win_dotRunpeX
{
	meta:
		author = "ditekSHen"
		description = "Detects dotRunpeX injector"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\TaskKill" fullword wide
		$s2 = "KoiVM" ascii
		$s3 = "RunpeX.Stub.Framework" wide
		$s4 = "ExceptionServices.ExceptionDispatchInfo" wide
		$s5 = "Kernel32.Dll" wide

	condition:
		uint16(0)==0x5a4d and all of them
}
