import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_CSPROJ
{
	meta:
		author = "ditekSHen"
		description = "Detects suspicious .CSPROJ files then compiled with msbuild"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "ToolsVersion=" ascii
		$s2 = "/developer/msbuild/" ascii
		$x1 = "[DllImport(\"\\x" ascii
		$x2 = "VirtualAlloc(" ascii nocase
		$x3 = "CallWindowProc(" ascii nocase

	condition:
		uint32(0)==0x6f72503c and ( all of ($s*) and 2 of ($x*))
}
