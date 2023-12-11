import "pe"

rule WMI_VM_Detect : WMI_VM_Detect
{
	meta:
		version = 2
		threat = "Using WMI to detect virtual machines via querying video card information"
		behaviour_class = "Evasion"
		author = "Joe Giron"
		date = "2015-09-25"
		description = "Detection of Virtual Appliances through the use of WMI for use of evasion."
		os = "windows"
		filetype = "executable"

	strings:
		$selstr = "SELECT Description FROM Win32_VideoController" nocase ascii wide
		$selstr2 = "SELECT * FROM Win32_VideoController" nocase ascii wide
		$vm1 = "virtualbox graphics adapter" nocase ascii wide
		$vm2 = "vmware svga ii" nocase ascii wide
		$vm3 = "vm additions s3 trio32/64" nocase ascii wide
		$vm4 = "parallel" nocase ascii wide
		$vm5 = "remotefx" nocase ascii wide
		$vm6 = "cirrus logic" nocase ascii wide
		$vm7 = "matrox" nocase ascii wide

	condition:
		any of ($selstr*) and any of ($vm*)
}
