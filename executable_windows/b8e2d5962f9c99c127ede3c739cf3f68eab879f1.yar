import "pe"

rule Check_VBox_VideoDrivers
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for reg keys of Vbox video drivers"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
		description = "Checks for VirtualBox video drivers in Windows registry"
		os = "windows"
		filetype = "executable"

	strings:
		$key = "HARDWARE\\Description\\System" nocase wide ascii
		$value = "VideoBiosVersion" wide nocase ascii
		$data = "VIRTUALBOX" nocase wide ascii

	condition:
		all of them
}
