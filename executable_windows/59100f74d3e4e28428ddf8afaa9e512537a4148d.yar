rule Lazarus_magicpoint_code
{
	meta:
		description = "magicpoint bot using Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash = "6f11c52f01e5696b1ac0faf6c19b0b439ba6f48f1f9851e34f0fa582b09dfa48"
		os = "windows"
		filetype = "executable"

	strings:
		$strPost1 = "mpVI=%s" ascii
		$strPost2 = "mpCMD=%s&mpVID=%s" ascii
		$strPost3 = "mpVCR=%s&mpID=%s" ascii
		$strMsg1 = "Error creating pipe" ascii
		$strMsg2 = "Error creating process" ascii
		$strFormat = "%c%c%c%s%c%s" ascii
		$strUA = "Mozilla/88.0" ascii
		$strMutex = "LGMUQTW" ascii
		$strData = "xz36" ascii
		$strcmd = "cmd.exe /c %s" ascii

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and 4 of ($str*)
}
