import "pe"

rule crime_win32_hvnc_banker_gen
{
	meta:
		description = "Detects malware banker hidden VNC"
		author = "@VK_Intel"
		reference = "https://twitter.com/VK_Intel/status/1247058432223477760"
		date = "2020-04-06"
		os = "windows"
		filetype = "executable"

	condition:
		pe.exports("VncStartServer") and pe.exports("VncStopServer")
}
