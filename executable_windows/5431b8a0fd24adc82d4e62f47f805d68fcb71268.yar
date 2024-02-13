rule malware_sqroot_snapshot
{
	meta:
		description = "snapshot plugin downloaded by sqroot"
		author = "JPCERT/CC Incident Response Group"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "e:\\vsprojects\\crataegus\\snaptik\\maz\\miniz.c" wide
		$s2 = "%s-%02d%02d_%02d%02d%02d.maz" wide
		$s3 = "%s%s_%02d%02d%02d(%d).png" wide
		$s4 = "gdi_cache" wide
		$s5 = "capture_flag.ini" wide
		$s6 = "cf_mptmb" wide
		$s7 = "cf_pakdir" wide
		$s8 = "DoGdiCapture" ascii

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and 4 of them
}
