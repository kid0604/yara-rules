import "pe"
import "math"

rule PystingerRule1
{
	meta:
		description = "Detect the risk of Malware Pystinger Rule 1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Failed to get address for PyImport_ExecCodeModule" fullword ascii
		$s2 = "Failed to get address for Py_NoUserSiteDirectory" fullword ascii
		$s3 = "Failed to get executable path." fullword ascii
		$s4 = "Failed to execute script %s" fullword ascii
		$s5 = "Failed to get address for PyMarshal_ReadObjectFromString" fullword ascii
		$s6 = "Failed to get address for Py_FileSystemDefaultEncoding" fullword ascii
		$s7 = "Failed to get address for PyRun_SimpleString" fullword ascii
		$s8 = "Failed to get address for PyUnicode_DecodeFSDefault" fullword ascii
		$s9 = "Failed to get address for PyUnicode_Decode" fullword ascii
		$s10 = "GVDVFVEVG" fullword ascii
		$s11 = "Failed to get address for Py_NoSiteFlag" fullword ascii
		$s12 = "Failed to get address for PySys_AddWarnOption" fullword ascii
		$s13 = "Failed to get address for PyErr_Clear" fullword ascii
		$s14 = "Failed to get address for Py_DecRef" fullword ascii
		$s15 = "Failed to get address for PyEval_EvalCode" fullword ascii
		$s16 = "Failed to get address for Py_BuildValue" fullword ascii
		$s17 = "Failed to get address for PyErr_Print" fullword ascii
		$s18 = "Failed to get address for _Py_char2wchar" fullword ascii
		$s19 = "logging.config(" fullword ascii
		$s20 = "Error loading Python DLL '%s'." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <13000KB and 8 of them
}
