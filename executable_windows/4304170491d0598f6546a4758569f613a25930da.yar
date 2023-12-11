import "pe"

rule MALWARE_Win_CRAT
{
	meta:
		author = "ditekSHen"
		description = "Detects CRAT main DLL"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "cmd /c \"dir %s /s >> %s\"" wide
		$s2 = "Set-Cookie:\\b*{.+?}\\n" wide
		$s3 = "Location: {[0-9]+}" wide
		$s4 = "Content-Disposition: form-data; name=\"%s\"; filename=\"" ascii
		$s6 = "%serror.log" wide
		$v2x_1 = "?timestamp=%u" wide
		$v2x_2 = "config.txt" wide
		$v2x_3 = "entdll.dll" wide
		$v2x_4 = "\\cmd.exe" wide
		$v2x_5 = "[MyDocuments]" wide
		$v2x_6 = "@SetWindowTextW FindFileExA" wide
		$v2x_7 = "Microsoft\\Windows\\WinX\\Group1\\*.exe" wide
		$v2s_1 = "Installed Anti Virus Programs" ascii
		$v2s_2 = "Running Processes" ascii
		$v2s_3 = "id=%u&content=" ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($s*) or 6 of ($v2x*) or all of ($v2s*) or (2 of ($v2s*) and 4 of ($v2x*)))
}
