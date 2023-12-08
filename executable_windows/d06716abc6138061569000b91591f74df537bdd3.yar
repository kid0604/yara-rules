import "pe"

rule crime_win32_dridex_socks5_mod
{
	meta:
		description = "Detects Dridex socks5 module"
		author = "@VK_Intel"
		date = "2020-04-06"
		reference = "https://twitter.com/VK_Intel/status/1247058432223477760"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "socks5_2_x32.dll"
		$s1 = "socks5_2_x64.dll"

	condition:
		any of ($s*) and pe.exports("start")
}
