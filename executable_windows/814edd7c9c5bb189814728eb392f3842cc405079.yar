import "pe"

rule APT9002Strings
{
	meta:
		description = "9002 Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-25"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "POST http://%ls:%d/%x HTTP/1.1"
		$ = "%%TEMP%%\\%s_p.ax" wide ascii
		$ = "%TEMP%\\uid.ax" wide ascii
		$ = "%%TEMP%%\\%s.ax" wide ascii
		$ = "sysinfo\x00sysbin01"
		$ = "\\FlashUpdate.exe"

	condition:
		any of them
}
