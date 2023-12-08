rule SeDLL_Javascript_Decryptor
{
	meta:
		description = "Detects SeDll - DLL is used for decrypting and executing another JavaScript backdoor such as Orz"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/MZ7dRg"
		date = "2017-10-18"
		modified = "2023-01-07"
		hash1 = "146aa9a0ec013aa5bdba9ea9d29f59d48d43bc17c6a20b74bb8c521dbb5bc6f4"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "SEDll_Win32.dll" fullword ascii
		$x2 = "regsvr32 /s \"%s\" DR __CIM__" wide
		$s1 = "WScriptW" fullword ascii
		$s2 = "IWScript" fullword ascii
		$s3 = "%s\\%s~%d" fullword wide
		$s4 = "PutBlockToFileWW" fullword ascii
		$s5 = "CheckUpAndDownWW" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <40KB and (1 of ($x*) or 4 of them )
}
