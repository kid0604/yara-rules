rule CryptHunter_lnk_bitly
{
	meta:
		description = "detect suspicious lnk file"
		author = "JPCERT/CC Incident Response Group"
		reference = "internal research"
		hash1 = "01b5cd525d18e28177924d8a7805c2010de6842b8ef430f29ed32b3e5d7d99a0"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "cmd.exe" wide ascii
		$a2 = "mshta" wide ascii
		$url1 = "https://bit.ly" wide ascii

	condition:
		( uint16(0)==0x004c) and ( filesize <100KB) and ((1 of ($a*)) and ($url1))
}
