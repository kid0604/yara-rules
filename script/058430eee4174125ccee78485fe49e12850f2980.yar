import "pe"
import "math"

rule PystingerRule2
{
	meta:
		description = "Detect the risk of Malware Pystinger Rule 2"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "Failed to execute script %s" fullword ascii
		$s2 = "Fatal error: unable to decode the command line argument #%i" fullword ascii
		$s3 = "logging.config(" fullword ascii
		$s4 = "Failed to get _MEIPASS as PyObject." fullword ascii
		$s5 = "Cannot dlsym for PyImport_ExecCodeModule" fullword ascii
		$s6 = "pyi-bootloader-ignore-signals" fullword ascii
		$s7 = "http.cookies(" fullword ascii
		$s8 = "wsgiref.headers(" fullword ascii
		$s9 = "Installing PYZ: Could not get sys.path" fullword ascii
		$s10 = "Failed to convert Wflag %s using mbstowcs (invalid multibyte string)" fullword ascii
		$s11 = "Error loading Python lib '%s': dlopen: %s" fullword ascii
		$s12 = "pyi-runtime-tmpdir" fullword ascii
		$s13 = "http.client(" fullword ascii
		$s14 = "e /p p$p8p4p," fullword ascii
		$s15 = "* s1_>" fullword ascii
		$s16 = "Could not get __main__ module." fullword ascii
		$s17 = "'6-2=2#232+" fullword ascii
		$s18 = "bunicodedata.so" fullword ascii
		$s19 = "boperator.so" fullword ascii
		$s20 = "Could not get __main__ module's dict." fullword ascii

	condition:
		uint16(0)==0x457f and filesize <19000KB and 8 of them
}
