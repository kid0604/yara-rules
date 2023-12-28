rule APT10_redleaves_strings
{
	meta:
		description = "RedLeaves malware"
		author = "JPCERT/CC Incident Response Group"
		hash = "ff0b79ed5ca3a5e1a9dabf8e47b15366c1d0783d0396af2cbba8e253020dbb34"
		os = "windows"
		filetype = "executable"

	strings:
		$v1a = "red_autumnal_leaves_dllmain.dll"
		$w1a = "RedLeavesCMDSimulatorMutex" wide

	condition:
		$v1a or $w1a
}
