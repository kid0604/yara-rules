import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_DeleteShimCache
{
	meta:
		author = "ditekSHen"
		description = "Detects executables embedding anti-forensic artifcats of deletiing shim cache"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Rundll32.exe apphelp.dll,ShimFlushCache" ascii wide nocase
		$s2 = "Rundll32 apphelp.dll,ShimFlushCache" ascii wide nocase
		$m1 = ".dll,ShimFlushCache" ascii wide nocase
		$m2 = "rundll32" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and (1 of ($s*) or all of ($m*))
}
