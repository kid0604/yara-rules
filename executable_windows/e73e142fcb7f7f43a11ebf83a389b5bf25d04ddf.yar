rule remcmdstub
{
	meta:
		description = "19438 - file remcmdstub.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/10/30/netsupport-intrusion-results-in-domain-compromise"
		date = "2023-10-29"
		hash1 = "fedd609a16c717db9bea3072bed41e79b564c4bc97f959208bfa52fb3c9fa814"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "remcmdstub.exe" fullword wide
		$s2 = "Usage: %s (4 InheritableEventHandles) (CommandLineToSpawn)" fullword ascii
		$s3 = "NetSupport Remote Command Prompt" fullword wide
		$s4 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
		$s5 = "remcmdstub" fullword wide
		$s6 = "NetSupport Ltd0" fullword ascii
		$s7 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
		$s8 = "NetSupport Ltd1" fullword ascii
		$s9 = "NetSupport Ltd" fullword wide
		$s10 = "!Copyright (c) 2015 NetSupport Ltd" fullword wide
		$s11 = "Copyright (c) 2015, NetSupport Ltd" fullword wide
		$s12 = "NetSupport School" fullword wide
		$s13 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPAD" ascii
		$s14 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii
		$s15 = "Peterborough1" fullword ascii
		$s16 = "  </trustInfo>" fullword ascii
		$s17 = "7.848>8" fullword ascii
		$s18 = "uTVWh/Y@" fullword ascii
		$s19 = ";-;4;8;<;@;D;H;L;P;" fullword ascii
		$s20 = "<8<?<D<H<L<m<" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 8 of them
}
