import "pe"

rule keyboy_systeminfo
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		desc = "Matches the system information format before sending to C2"
		date = "2016-08-28"
		md5 = "495adb1b9777002ecfe22aaf52fcee93"
		description = "Matches the system information format before sending to C2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "SystemVersion:    %s" ascii wide
		$s2 = "Product  ID:      %s" ascii wide
		$s3 = "InstallPath:      %s" ascii wide
		$s4 = "InstallTime:      %d-%d-%d, %02d:%02d:%02d" ascii wide
		$s5 = "ResgisterGroup:   %s" ascii wide
		$s6 = "RegisterUser:     %s" ascii wide
		$s7 = "ComputerName:     %s" ascii wide
		$s8 = "WindowsDirectory: %s" ascii wide
		$s9 = "System Directory: %s" ascii wide
		$s10 = "Number of Processors:       %d" ascii wide
		$s11 = "CPU[%d]:  %s: %sMHz" ascii wide
		$s12 = "RAM:         %dMB Total, %dMB Free." ascii wide
		$s13 = "DisplayMode: %d x %d, %dHz, %dbit" ascii wide
		$s14 = "Uptime:      %d Days %02u:%02u:%02u" ascii wide

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and filesize <200KB and 7 of them
}
