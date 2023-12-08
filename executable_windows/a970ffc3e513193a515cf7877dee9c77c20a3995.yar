import "pe"

rule Reflective_DLL_Loader_Aug17_1
{
	meta:
		description = "Detects Reflective DLL Loader"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-08-20"
		hash1 = "f2f85855914345eec629e6fc5333cf325a620531d1441313292924a88564e320"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\Release\\reflective_dll.pdb" ascii
		$x2 = "reflective_dll.x64.dll" fullword ascii
		$s3 = "DLL Injection" fullword ascii
		$s4 = "?ReflectiveLoader@@YA_KPEAX@Z" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and (pe.imphash()=="4bf489ae7d1e6575f5bb81ae4d10862f" or pe.exports("?ReflectiveLoader@@YA_KPEAX@Z") or (1 of ($x*) or 2 of them ))) or (2 of them )
}
