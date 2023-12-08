import "pe"

rule MALWARE_Win_CelestyBinderLoader
{
	meta:
		author = "ditekSHen"
		description = "Detects Celesty Binder loader"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\DarkCoderSc\\Desktop\\Celesty Binder\\Stub\\STATIC\\Stub.pdb" ascii
		$s2 = "DROPIN" fullword ascii wide
		$s3 = "EXEC" fullword ascii wide
		$s4 = "RBIND" fullword ascii wide
		$s5 = "%LAPPDATA%" fullword ascii wide
		$s6 = "%USERDIR%" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and all of them
}
