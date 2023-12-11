import "pe"
import "math"

rule IsNET_DLL : PECheck
{
	meta:
		description = "Checks if the PE file imports _CorDllMain from mscoree.dll, indicating it may be a .NET DLL"
		os = "windows"
		filetype = "executable"

	condition:
		pe.imports("mscoree.dll","_CorDllMain")
}
