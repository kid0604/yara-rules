rule APT_PY_BlueLight_Loader : InkySquid
{
	meta:
		author = "threatintel@volexity.com"
		description = "Python Loader used to execute the BLUELIGHT malware family."
		date = "2021-06-22"
		hash1 = "80269413be6ad51b8b19631b2f5559c9572842e789bbce031babe6e879d2e120"
		license = "See license at https://github.com/volexity/threat-intel/LICENSE.txt"
		reference = "https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "\"\".join(chr(ord(" ascii
		$s2 = "import ctypes " ascii
		$s3 = "ctypes.CFUNCTYPE(ctypes.c_int)" ascii
		$s4 = "ctypes.memmove" ascii
		$s5 = "python ended" ascii

	condition:
		all of them
}
