import "pe"
import "math"

rule IsNET_EXE : PECheck
{
	meta:
		description = "Detects .NET executable files"
		os = "windows"
		filetype = "executable"

	condition:
		pe.imports("mscoree.dll","_CorExeMain")
}
