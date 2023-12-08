import "math"
import "pe"

rule MinGW_1
{
	meta:
		author = "_pusher_"
		date = "2016-07"
		description = "Detects MinGW compiler usage based on specific strings and linker version"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = "msvcrt.dll" ascii nocase
		$aa1 = "Mingw-w64 runtime failure:"
		$aa2 = "-LIBGCCW32-EH-3-SJLJ-GTHR-MINGW32" wide ascii nocase
		$aa3 = "_mingw32_init_mainargs"
		$aa4 = "mingw32"
		$aa5 = "-LIBGCCW32-EH-2-SJLJ-GTHR-MINGW32" wide ascii nocase
		$aa6 = "-GCCLIBCYGMING-EH-TDM1-SJLJ-GTHR-MINGW32" wide ascii nocase
		$aa7 = "Mingw runtime failure:"

	condition:
		((pe.linker_version.major==2) and (pe.linker_version.minor==56) or (pe.linker_version.major==2) and ((pe.linker_version.minor>=21) and (pe.linker_version.minor<=25))) and ($a0 and ( any of ($aa*)))
}
