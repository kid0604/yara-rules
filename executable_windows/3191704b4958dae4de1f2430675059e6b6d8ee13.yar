import "pe"

rule IceID_Bank_trojan
{
	meta:
		description = "Detects IcedID..adjusted several times"
		author = "unixfreaxjp"
		org = "MalwareMustDie"
		date = "2018-01-14"
		os = "windows"
		filetype = "executable"

	strings:
		$header = { 4D 5A }
		$magic1 = { E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 6A ?? 68 ?? ?? }
		$st01 = "CCmdTarget" fullword nocase wide ascii
		$st02 = "CUserException" fullword nocase wide ascii
		$st03 = "FileType" fullword nocase wide ascii
		$st04 = "FlsGetValue" fullword nocase wide ascii
		$st05 = "AVCShellWrapper@@" fullword nocase wide ascii
		$st06 = "AVCCmdTarget@@" fullword nocase wide ascii
		$st07 = "AUCThreadData@@" fullword nocase wide ascii
		$st08 = "AVCUserException@@" fullword nocase wide ascii

	condition:
		$header at 0 and all of ($magic*) and 6 of ($st0*) and pe.sections[0].name contains ".text" and pe.sections[1].name contains ".rdata" and pe.sections[2].name contains ".data" and pe.sections[3].name contains ".rsrc" and pe.characteristics&pe.EXECUTABLE_IMAGE and pe.characteristics&pe.RELOCS_STRIPPED
}
