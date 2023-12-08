import "pe"

rule keyboy_commands
{
	meta:
		author = "Matt Brooks, @cmatthewbrooks"
		desc = "Matches the 2016 sample's sent and received commands"
		date = "2016-08-28"
		md5 = "495adb1b9777002ecfe22aaf52fcee93"
		description = "Matches the 2016 sample's sent and received commands"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Update" wide fullword
		$s2 = "UpdateAndRun" wide fullword
		$s3 = "Refresh" wide fullword
		$s4 = "OnLine" wide fullword
		$s5 = "Disconnect" wide fullword
		$s6 = "Pw_Error" wide fullword
		$s7 = "Pw_OK" wide fullword
		$s8 = "Sysinfo" wide fullword
		$s9 = "Download" wide fullword
		$s10 = "UploadFileOk" wide fullword
		$s11 = "RemoteRun" wide fullword
		$s12 = "FileManager" wide fullword

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and filesize <200KB and 6 of them
}
