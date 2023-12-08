import "pe"

rule WiltedTulip_Tools_clrlg
{
	meta:
		description = "Detects Windows eventlog cleaner used in Operation Wilted Tulip - file clrlg.bat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		hash1 = "b33fd3420bffa92cadbe90497b3036b5816f2157100bf1d9a3b6c946108148bf"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "('wevtutil.exe el') DO (call :do_clear" fullword ascii
		$s2 = "wevtutil.exe cl %1" fullword ascii

	condition:
		filesize <1KB and 1 of them
}
