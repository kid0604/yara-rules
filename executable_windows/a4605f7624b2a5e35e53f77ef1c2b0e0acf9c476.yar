rule malware_sqroot_pluginloader
{
	meta:
		description = "plugin loader downloaded by sqroot"
		author = "JPCERT/CC Incident Response Group"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "Active() found" ascii
		$a2 = "Active:Thread created!" ascii
		$b1 = {6A 74 70 61 00}
		$b2 = {6A 74 70 63 00}
		$b3 = {6A 74 70 74 00}
		$b4 = "%s*.tmp" ascii
		$c1 = "SignalS1" ascii
		$c2 = "SignalS2" ascii
		$c3 = "SignalS3" ascii

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and 5 of them
}
