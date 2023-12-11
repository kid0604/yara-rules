rule adjustcr
{
	meta:
		description = "Webshells Auto-generated - file adjustcr.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "17037fa684ef4c90a25ec5674dac2eb6"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "$Info: This file is packed with the UPX executable packer $"
		$s2 = "$License: NRV for UPX is distributed under special license $"
		$s6 = "AdjustCR Carr"
		$s7 = "ION\\System\\FloatingPo"

	condition:
		all of them
}
