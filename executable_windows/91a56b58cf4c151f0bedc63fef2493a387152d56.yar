rule RE_Tools
{
	meta:
		description = "Contains references to debugging or reversing tools"
		author = "Ivan Kwiatkowski (@JusticeRage)"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = /ida(q)?(64)?.exe/ nocase wide ascii
		$a1 = "ImmunityDebugger.exe" nocase wide ascii
		$a2 = "ollydbg.exe" nocase wide ascii
		$a3 = "lordpe.exe" nocase wide ascii
		$a4 = "peid.exe" nocase wide ascii
		$a5 = "windbg.exe" nocase wide ascii

	condition:
		any of them
}
