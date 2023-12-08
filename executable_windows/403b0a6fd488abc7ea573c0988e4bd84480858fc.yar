import "pe"

rule Reflective_DLL_Loader_Aug17_2
{
	meta:
		description = "Detects Reflective DLL Loader - suspicious - Possible FP could be program crack"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-08-20"
		score = 60
		hash1 = "c2a7a2d0b05ad42386a2bedb780205b7c0af76fe9ee3d47bbe217562f627fcae"
		hash2 = "b90831aaf8859e604283e5292158f08f100d4a2d4e1875ea1911750a6cb85fe0"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\ReflectiveDLLInjection-master\\" ascii
		$s2 = "reflective_dll.dll" fullword ascii
		$s3 = "DLL injection" fullword ascii
		$s4 = "_ReflectiveLoader@4" ascii
		$s5 = "Reflective Dll Injection" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <200KB and (pe.imphash()=="59867122bcc8c959ad307ac2dd08af79" or pe.exports("_ReflectiveLoader@4") or 2 of them )) or (3 of them )
}
