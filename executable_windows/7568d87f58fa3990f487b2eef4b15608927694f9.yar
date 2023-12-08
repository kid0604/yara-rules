rule INDICATOR_TOOL_GoCLR
{
	meta:
		author = "ditekSHen"
		description = "Detects binaries utilizing Go-CLR for hosting the CLR in a Go process and using it to execute a DLL from disk or an assembly from memory"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "github.com/ropnop/go-clr.(*IC" ascii
		$s2 = "EnumKeyExWRegEnumValueWRegOpenKeyExWRtlCopyMemoryRtlGetVersionShellExecuteWStartServiceW" ascii
		$c1 = "ICorRuntimeHost" ascii wide
		$c2 = "CLRCreateInstance" ascii wide
		$c3 = "ICLRRuntimeInfo" ascii wide
		$c4 = "ICLRMetaHost" ascii wide
		$go = "Go build ID:" ascii wide

	condition:
		uint16(0)==0x5a4d and all of ($s*) or (2 of ($c*) and $go)
}
