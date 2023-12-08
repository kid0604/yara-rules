rule ZXshell2_0_rar_Folder_zxrecv
{
	meta:
		description = "Webshells Auto-generated - file zxrecv.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "5d3d12a39f41d51341ef4cb7ce69d30f"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "RyFlushBuff"
		$s1 = "teToWideChar^FiYP"
		$s2 = "mdesc+8F D"
		$s3 = "\\von76std"
		$s4 = "5pur+virtul"
		$s5 = "- Kablto io"
		$s6 = "ac#f{lowi8a"

	condition:
		all of them
}
