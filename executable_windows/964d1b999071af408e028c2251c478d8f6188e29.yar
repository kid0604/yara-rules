import "pe"
import "math"

rule Cygwin : Red Hat
{
	meta:
		author = "_pusher_"
		date = "2016-07"
		description = "Detects the presence of Cygwin on a system"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = "cygwin1.dll" ascii nocase
		$aa1 = "cygwin_internal"
		$aa2 = "cygwin_detach_dll"

	condition:
		((pe.linker_version.major==2) and (pe.linker_version.minor==56) or (pe.linker_version.major==2) and (pe.linker_version.minor==24) or (pe.linker_version.major==2) and (pe.linker_version.minor==25)) and ($a0 and ( any of ($aa*)))
}
